"""One-shot migration runner — called by ECS run-task override."""
import asyncio, os, sys
sys.path.insert(0, "/app")

async def main():
    from sqlalchemy.ext.asyncio import create_async_engine
    from sqlalchemy import text

    db_url = os.environ["DATABASE_URL"]
    engine = create_async_engine(db_url)

    sql_path = "/app/backend/migrations/add_us_compliance_controls.sql"
    with open(sql_path) as f:
        raw = f.read()

    # Strip comments and split on semicolons
    stmts = []
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("--") or not line:
            continue
        stmts.append(line)
    full_sql = " ".join(stmts)

    async with engine.begin() as conn:
        try:
            await conn.execute(text(full_sql))
            print("✅ Migration applied: US compliance controls inserted")
        except Exception as e:
            print(f"Migration result: {e}")

    await engine.dispose()

asyncio.run(main())
