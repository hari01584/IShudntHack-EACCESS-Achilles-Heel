import asyncio

import pyrcrack

from rich.console import Console
from rich.prompt import Prompt


async def scan_for_targets():
    """Scan for targets, return json."""
    console = Console()
    console.clear()
    console.show_cursor(False)
    airmon = pyrcrack.AirmonNg()

    try:
        infcs = [a['interface'] for a in await airmon.interfaces]
    except Exception as e:
        print(e)
        print("Are you running root?")
        exit(0)

    interface = Prompt.ask(
        'Select an interface',
        choices=infcs)

    async with airmon(interface) as mon:
        async with pyrcrack.AirodumpNg() as pdump:
            async for result in pdump(mon.monitor_interface):
                console.clear()
                console.print(result.table)
                await asyncio.sleep(2)


asyncio.run(scan_for_targets())
