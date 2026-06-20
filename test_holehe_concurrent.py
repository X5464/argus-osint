import asyncio
import httpx
from holehe import core as holehe_core
import holehe.modules

async def run():
    client = httpx.AsyncClient()
    modules_dict = holehe_core.import_submodules("holehe.modules")
    websites = holehe_core.get_functions(modules_dict)
    out_list = []
    print(f"Loaded {len(websites)} websites")
    try:
        tasks = [func('test@example.com', client, out_list) for func in websites]
        await asyncio.gather(*tasks, return_exceptions=True)
    except Exception as e:
        print(f"Error: {e}")
    finally:
        await client.aclose()
    print(f"Finished. Extracted {len(out_list)} results.")

asyncio.run(run())
