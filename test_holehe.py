import asyncio
import httpx
from holehe import core as holehe_core
import holehe.modules

async def run():
    client = httpx.AsyncClient()
    modules_dict = holehe_core.import_submodules("holehe.modules")
    websites = holehe_core.get_functions(modules_dict)
    out = []
    print(f"Loaded {len(websites)} websites")
    try:
        await holehe_core.launch_module(websites[0], 'test@example.com', client, out)
    except Exception as e:
        print(f"Error: {e}")
    finally:
        await client.aclose()
    print(out)

asyncio.run(run())
