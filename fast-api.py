from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
from typing import Optional
import httpx
import os
import re
from dotenv import load_dotenv
from functools import lru_cache

# Load environment variables
load_dotenv('api.env')

# App instance
app = FastAPI(title="Dremio Query API")

# Dremio config
DREMIO_URL = os.getenv("DREMIO_URL")
DREMIO_USERNAME = os.getenv("DREMIO_USERNAME")
DREMIO_PASSWORD = os.getenv("DREMIO_PASSWORD")
print(DREMIO_URL)
# Harmful SQL commands to block
HARMFUL_COMMANDS = r'\b(DROP|DELETE|INSERT|UPDATE|ALTER|CREATE|TRUNCATE|REPLACE|MERGE|EXEC|EXECUTE|GRANT|REVOKE|SET|USE|CALL|LOCK|UNLOCK|RENAME|COMMENT|COMMIT|ROLLBACK|SAVEPOINT|RELEASE)\b'


# ----------------------------- MODELS -----------------------------

class SQLQuery(BaseModel):
    sql: str


# ----------------------------- UTILS -----------------------------

@lru_cache()
def get_dremio_token() -> str:
    """Authenticate with Dremio and return token (cached)."""
    response = httpx.post(f"{DREMIO_URL}/apiv2/login", json={
        "userName": DREMIO_USERNAME,
        "password": DREMIO_PASSWORD
    })

    if response.status_code != 200:
        raise HTTPException(status_code=500, detail="Authentication with Dremio failed.")

    return response.json().get("token")


def validate_sql(sql: str):
    """Ensure the query is a safe SELECT statement."""
    if not re.match(r"^\s*SELECT\b", sql.strip(), re.IGNORECASE) or re.search(HARMFUL_COMMANDS, sql, re.IGNORECASE):
        raise HTTPException(
            status_code=400,
            detail="Only SELECT queries are allowed, and no harmful SQL commands are permitted."
        )


# ----------------------------- DREMIO LOGIC -----------------------------

async def execute_dremio_query(sql: str) -> str:
    """Submit SQL to Dremio and return job ID."""
    token = get_dremio_token()
    headers = {
        "Authorization": f"_dremio{token}",
        "Content-Type": "application/json"
    }

    async with httpx.AsyncClient() as client:
        response = await client.post(f"{DREMIO_URL}/api/v3/sql", headers=headers, json={"sql": sql})
        response.raise_for_status()
        return response.json().get("id")


async def poll_dremio_job(job_id: str) -> dict:
    """Poll Dremio job until complete, then fetch results."""
    token = get_dremio_token()
    headers = {
        "Authorization": f"_dremio{token}",
        "Content-Type": "application/json"
    }

    async with httpx.AsyncClient() as client:
        while True:
            status_response = await client.get(f"{DREMIO_URL}/api/v3/job/{job_id}", headers=headers)
            status_response.raise_for_status()

            job_status = status_response.json().get("jobState")
            if job_status == "COMPLETED":
                break
            elif job_status in ("FAILED", "CANCELED"):
                raise HTTPException(status_code=500, detail=f"Query failed with status: {job_status}")

        result_response = await client.get(f"{DREMIO_URL}/api/v3/job/{job_id}/results", headers=headers)
        result_response.raise_for_status()

        return result_response.json()


async def get_dremio_catalog() -> dict:
    """Fetch Dremio catalog."""
    token = get_dremio_token()
    headers = {
        "Authorization": f"_dremio{token}",
        "Content-Type": "application/json"
    }

    async with httpx.AsyncClient() as client:
        response = await client.get(f"{DREMIO_URL}/api/v3/catalog", headers=headers)
        response.raise_for_status()
        return response.json()


# ----------------------------- ROUTES -----------------------------

@app.post("/dremio/query")
async def run_query(payload: SQLQuery):
    validate_sql(payload.sql)
    try:
        job_id = await execute_dremio_query(payload.sql)
        result = await poll_dremio_job(job_id)
        return result
    except httpx.HTTPError as e:
        raise HTTPException(status_code=500, detail=f"Dremio API error: {str(e)}")


@app.get("/dremio/catalog")
async def catalog():
    try:
        catalog_data = await get_dremio_catalog()
        return catalog_data
    except httpx.HTTPError as e:
        raise HTTPException(status_code=500, detail=f"Dremio catalog fetch failed: {str(e)}")

async def list_dremio_sources() -> list:
    """Return a list of sources from the Dremio catalog."""
    token = get_dremio_token()
    headers = {
        "Authorization": f"_dremio{token}",
        "Content-Type": "application/json"
    }

    async with httpx.AsyncClient() as client:
        response = await client.get(f"{DREMIO_URL}/api/v3/source", headers=headers)
        response.raise_for_status()
        items = response.json().get("data", [])
        sources = [item for item in items if item.get("type") != "HOME"]
        return items
    
@app.get("/dremio/sources")
async def sources():
    try:
        sources_data = await list_dremio_sources()
        return sources_data
    except httpx.HTTPError as e:
        raise HTTPException(status_code=500, detail=f"Dremio sources fetch failed: {str(e)}")
    
@app.get("/")
async def root():
    return {"message": "Dremio FastAPI is running"}