import asyncio
import pyrcrack
import io, json

from rich.console import Console
from rich.prompt import Prompt

async def displayBisect(result):
    clients = []
    for ap in result:
        for client in ap.clients:
            clients.append(client)

    clients.sort(key=lambda x: x.dbm)
    jsonstr1 = json.dumps([{"bssid": ob.bssid, "packet":ob.packets, "dbm":ob.dbm} for ob in clients], indent=4)

    with io.open('devices.json', 'w', encoding='utf-8') as f:
        f.write(jsonstr1)

    for c in clients:
        print(c.bssid, c.dbm, c.packets)

async def scan_for_targets():
    """Scan for targets, return json."""
    console = Console()
    console.clear()
    console.show_cursor(False)
    airmon = pyrcrack.AirmonNg()
    
    try:
        infcs = [a.interface for a in await airmon.interfaces]
    except Exception as e:
        print(e)
        print("Are you running root?")
        exit(0)

    interface = Prompt.ask(
        'Select an interface',
        choices=infcs)
    # interface = "wlan1" #DEBUG

    print("Selected interface %s"%(interface))

    async with airmon(interface) as mon:
        async with pyrcrack.AirodumpNg() as pdump:
            async for result in pdump(mon.monitor_interface):
                console.clear()
                console.print(result.table)

                await displayBisect(result)

                await asyncio.sleep(2)


asyncio.run(scan_for_targets())
