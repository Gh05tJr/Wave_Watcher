import os
import subprocess
import sys
import time
import threading
import re
import logging
import queue
from datetime import datetime
from playsound import playsound

from scapy.all import sniff, Dot11Deauth, Dot11Disas, Dot11Beacon, Dot11ProbeResp, RadioTap, Dot11, Dot11Elt

# Rich Display Modules
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.console import Group
from rich.text import Text

Red="\033[38;5;197m"
Green="\033[38;5;47m"
Yellow="\033[38;5;11m"
Cyan="\033[38;5;44m"
White="\033[0;37m"
Orange="\033[38;5;215m"
Orange_Light="\x1b[38;5;222m"
NC="\033[00m"

Ask  =     f"{Cyan}[{White}?{Cyan}] {Cyan}"
Success = f"{Green}[{White}√{Green}] {Green}"
Error  =    f"{Red}[{White}!{Red}] {Red}"
Warning  =    f"{Red}[{White}x{Red}] {Red}"
Info  =   f"{Orange}[{White}+{Orange}] {Orange}"
Info_2  =   f"{Orange_Light}[{White}•{Orange_Light}] {Orange_Light}"

Version="1.0"

Logo = fr"""
{Cyan} __        __               __        __    _       _
{Cyan} \ \      / /_ ___   _____  \ \      / /_ _| |_ ___| |__   ___ _ __
{Cyan}  \ \ /\ / / _` \ \ / / _ \  \ \ /\ / / _` | __/ __| '_ \ / _ \ '__|
{Cyan}   \ V  V / (_| |\ V /  __/   \ V  V / (_| | || (__| | | |  __/ |
{Cyan}    \_/\_/ \__,_| \_/ \___|    \_/\_/ \__,_|\__\___|_| |_|\___|_|
{" "*42}{Red}Operation: Static Shift{Orange}
{Orange}{" "*59}[{Yellow}v{Version}{Orange}]
{Orange}{" "*53}""" + f"[{Yellow}By {Green}\x47\x68\x30\x35\x74\x4a\x72{Orange}]" + fr"""
"""

# Suppress Scapy's harmless socket shutdown warnings when interfaces reset
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# --- CONFIGURATION THRESHOLDS ---
Attack_Threshold = 8        # Packets per window to trigger DoS alert
Beacon_Flood_Threshold = 10 # Unique NEW BSSIDs per 3-sec window
AUDIO_COOLDOWN_SECS = 4.0  

# --- DYNAMIC BASELINE CONFIGURATION ---
Baseline_Scan_Cycles = 2    # Full spectrum sweeps to learn clean environment
Baseline_Completed = False  
Completed_Cycles = 0        

# DYNAMIC BASELINE STORAGE
Dynamic_Baseline = {} 

def Clean_String(val):
    return re.sub(r'[\W_]+', '', str(val).lower().strip())

# Spectrum Channels
Channels_2_GHz = [1, 6, 11, 2, 3, 4, 5, 7, 8, 9, 10, 12, 13]
Channels_5_GHz = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 149, 153, 157, 161]
All_Channels = Channels_2_GHz + Channels_5_GHz

# --- GLOBAL TRACKERS & LOCKS ---
Tracker_Lock = threading.Lock()
Keep_Running = True         
Audio_Queue = queue.Queue() 
Packet_Queue = queue.Queue() 
Last_Audio_Time = {}        

Last_Attack_Time = 0.0      
Current_Channel = 1         

Deauth_Packet_Log = []  
Active_Attacks = {}     
Network_Status = {}     
Attack_Logs = []        

AP_Clients = {}

Deauth_Pending_Stops = {} 

Seen_BSSIDs = {}        
Rogue_AP_Tracker = {}   

# Global state flags to restrict audio triggers to 1 alert per attack category
Deauth_Global_Active = False
Beacon_Flood_Active = False
Rogue_AP_Active = False

logging.basicConfig(
    filename='Wave_Watcher_Alerts.log',filemode='a', 
    level=logging.INFO,format='%(asctime)s - [%(levelname)s] - %(message)s',datefmt='%Y-%m-%d %H:%M:%S'
)

def Get_Band_String(channel_num):
    try:
        ch = int(channel_num)
        if 1 <= ch <= 14:
            return "2.4 GHz"
        elif 32 <= ch <= 177:
            return "5 GHz"
        elif ch > 177:
            return "6 GHz"
    except Exception:
        pass
    return "Unknown"

def Get_WiFi_Interfaces():
    try:
        return os.listdir('/sys/class/net/')
    except Exception:
        return []

def Enable_Monitor_Mode(WiFi_Interface):
    try:
        subprocess.run(["airmon-ng", "check", "kill"], stdout=subprocess.DEVNULL)
        subprocess.run(["airmon-ng", "start", WiFi_Interface], stdout=subprocess.DEVNULL, check=True)
        active_interfaces = Get_WiFi_Interfaces()
        mon_Interface = f"{WiFi_Interface}mon"
        Target_Interface = mon_Interface if mon_Interface in active_interfaces else WiFi_Interface
        subprocess.run(["ip", "link", "set", Target_Interface, "up"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return Target_Interface
    except Exception:
        return None

def Disable_Monitor_Mode(mon_Interface):
    subprocess.run(["airmon-ng", "stop", mon_Interface], stdout=subprocess.DEVNULL)
    subprocess.run(["systemctl", "start", "NetworkManager"], stdout=subprocess.DEVNULL)

def Get_SSID_From_Packet(Packet):
    if not Packet.haslayer(Dot11Elt):
        return "Hidden"
    
    try:
        elt = Packet[Dot11Elt]
        while isinstance(elt, Dot11Elt):
            if elt.ID == 0: 
                if elt.info:
                    raw_bytes = bytes(elt.info)
                    clean_bytes = raw_bytes.replace(b'\x00', b'').strip()
                    if clean_bytes:
                        return clean_bytes.decode('utf-8', errors='ignore').strip()
            elt = elt.payload.getlayer(Dot11Elt)
    except Exception:
        pass

    return "Hidden"

def Get_BSSID_From_Packet(Packet):
    if not Packet.haslayer(Dot11):
        return None
    bssid = Packet.addr3 or Packet.addr2 or Packet.addr1
    if bssid and bssid.lower() not in ["ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"]:
        return bssid.lower().strip()
    return None

def Play_Audio_Debounced(Audio_File, Category):
    Current_Time = time.time()
    last_played = Last_Audio_Time.get(Category, 0)
    
    if Current_Time - last_played >= AUDIO_COOLDOWN_SECS:
        Last_Audio_Time[Category] = Current_Time
        Audio_Queue.put(Audio_File)

def Audio_Playback_Worker():
    while Keep_Running:
        try:
            Audio_File = Audio_Queue.get(timeout=1.0)
            if os.path.exists(Audio_File):
                try:
                    playsound(Audio_File)
                except Exception as e:
                    logging.error(f"Audio Error: {str(e)}")
            Audio_Queue.task_done()
        except queue.Empty:
            continue

def Channel_Hopper(WiFi_Interface):
    global Current_Channel, Baseline_Completed, Completed_Cycles
    
    while Keep_Running:
        if not Baseline_Completed:
            for cycle in range(1, Baseline_Scan_Cycles + 1):
                for Channel in All_Channels:
                    if not Keep_Running:
                        return
                    with Tracker_Lock:
                        Current_Channel = Channel
                    try:
                        subprocess.run(["iwconfig", WiFi_Interface, "channel", str(Channel)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        time.sleep(0.3)
                    except Exception:
                        break
                with Tracker_Lock:
                    Completed_Cycles = cycle

            with Tracker_Lock:
                Baseline_Completed = True
                logging.info(f"Dynamic Baseline Complete. Learned {len(Dynamic_Baseline)} SSIDs automatically.")
                Audio_Queue.put("Audio/Baseline Created.mp3")

        for Channel in All_Channels:
            if not Keep_Running:
                break
            with Tracker_Lock:
                Current_Channel = Channel

            try:
                subprocess.run(["iwconfig", WiFi_Interface, "channel", str(Channel)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                time.sleep(0.18)
            except Exception:
                break

def Evaluate_Dynamic_Baseline(scanned_bssid, scanned_ssid, timestamp_str, current_time):
    global Rogue_AP_Active, Attack_Logs, Active_Attacks, Last_Attack_Time, Dynamic_Baseline

    if not scanned_ssid or scanned_ssid == "Hidden":
        return

    scanned_ssid_clean = Clean_String(scanned_ssid)
    scanned_bssid_clean = scanned_bssid.lower().strip()

    if not Baseline_Completed:
        if scanned_ssid_clean not in Dynamic_Baseline:
            Dynamic_Baseline[scanned_ssid_clean] = set()
        Dynamic_Baseline[scanned_ssid_clean].add(scanned_bssid_clean)
        return

    if scanned_ssid_clean in Dynamic_Baseline:
        known_trusted_bssids = Dynamic_Baseline[scanned_ssid_clean]
        
        if scanned_bssid_clean not in known_trusted_bssids:
            Dict_Key = f"Rogue_AP_{scanned_ssid_clean}_{scanned_bssid_clean}"
            Rogue_AP_Tracker[Dict_Key] = current_time
            Last_Attack_Time = current_time
            
            Active_Attacks[Dict_Key] = {
                "Attacker": scanned_bssid,"Target": scanned_ssid, 
                "Rate": 1, "Last_Seen": current_time, 
                "Status": "ACTIVE", "Type": "Rogue AP / Evil Twin"
            }
            
            if not Rogue_AP_Active:
                Rogue_AP_Active = True
                Attack_Logs.append({
                    "Time": timestamp_str,"Type": "Rogue AP / Evil Twin", 
                    "Attacker": scanned_bssid, "Target": scanned_ssid, "Event": "Rogue AP Detected"
                })
                logging.warning(f"Rogue AP Detected! SSID: {scanned_ssid} | BSSID: {scanned_bssid}")
                Play_Audio_Debounced("Audio/Rogue_Start.mp3", "Rogue_Start")

def Alert_Evaluator():
    global Active_Attacks, Attack_Logs, Beacon_Flood_Active, Rogue_AP_Active, Deauth_Global_Active
    global Network_Status, Deauth_Packet_Log, Last_Attack_Time, Deauth_Pending_Stops

    while Keep_Running:
        time.sleep(0.3)
        if not Keep_Running or not Baseline_Completed:
            continue

        Current_Time = time.time()
        Timestamp_str = datetime.now().strftime("%H:%M:%S")
        
        with Tracker_Lock:
            Stale_BSSIDs = [BSSID for BSSID, Info in Network_Status.items() if Current_Time - Info["Last_Seen"] > 15.0]
            for BSSID in Stale_BSSIDs:
                del Network_Status[BSSID]
                if BSSID in AP_Clients:
                    del AP_Clients[BSSID]

            Deauth_Packet_Log[:] = [entry for entry in Deauth_Packet_Log if Current_Time - entry[0] <= 3.0]
            
            Active_Deauth_Pairs = {}
            for ts, src, dst, ch in Deauth_Packet_Log:
                pair = (src, dst)
                Active_Deauth_Pairs[pair] = Active_Deauth_Pairs.get(pair, 0) + 1

            for (Source_MAC, Target_MAC), Count in Active_Deauth_Pairs.items():
                Rate_Per_Sec = int(Count / 3.0)
                Pair_Key = (Source_MAC, Target_MAC)
                Dict_Key = f"Deauth_{Source_MAC}_{Target_MAC}"

                if Count >= Attack_Threshold:
                    Last_Attack_Time = Current_Time

                    if Pair_Key in Deauth_Pending_Stops:
                        del Deauth_Pending_Stops[Pair_Key]

                    if Dict_Key not in Active_Attacks:
                        Attack_Logs.append({
                            "Time": Timestamp_str,"Type": "Deauth Flood / DOS", 
                            "Attacker": Source_MAC,"Target": Target_MAC,"Event": "Attack Detected"
                        })
                        logging.warning(f"Deauth Attack Started | {Source_MAC} -> {Target_MAC}")
                        
                        if not Deauth_Global_Active:
                            Deauth_Global_Active = True
                            Play_Audio_Debounced("Audio/Deauth_Start.mp3", "Deauth_Start")

                    Active_Attacks[Dict_Key] = {
                        "Attacker": Source_MAC,"Target": Target_MAC,
                        "Rate": Rate_Per_Sec,"Last_Seen": Current_Time,
                        "Status": "ACTIVE","Type": "Deauth Flood / DOS"
                    }

            for Key in list(Active_Attacks.keys()):
                Info = Active_Attacks[Key]
                if "Deauth Flood" in Info["Type"]:
                    Pair_Key = (Info["Attacker"], Info["Target"])
                    
                    if Pair_Key not in Active_Deauth_Pairs or Active_Deauth_Pairs[Pair_Key] < Attack_Threshold:
                        if Pair_Key not in Deauth_Pending_Stops:
                            Deauth_Pending_Stops[Pair_Key] = Current_Time
                        else:
                            Elapsed = Current_Time - Deauth_Pending_Stops[Pair_Key]
                            if Elapsed >= 4.0:
                                Attack_Logs.append({
                                    "Time": Timestamp_str, "Type": "Deauth Flood / DOS", 
                                    "Attacker": Info["Attacker"], "Target": Info["Target"], "Event": "Attack Cleared"
                                })
                                logging.info(f"Deauth Attack Cleared: {Info['Attacker']} -> {Info['Target']}")
                                
                                del Active_Attacks[Key]
                                del Deauth_Pending_Stops[Pair_Key]

            has_active_deauth = any("Deauth Flood" in info["Type"] for info in Active_Attacks.values())
            if Deauth_Global_Active and not has_active_deauth:
                Deauth_Global_Active = False
                Play_Audio_Debounced("Audio/Deauth_Stop.mp3", "Deauth_Stop")

            Recent_BSSIDs = [mac for mac, last_seen in Seen_BSSIDs.items() if Current_Time - last_seen <= 3.0]
            
            if len(Recent_BSSIDs) >= Beacon_Flood_Threshold:
                Last_Attack_Time = Current_Time
                if not Beacon_Flood_Active:
                    Beacon_Flood_Active = True
                    Attack_Logs.append({"Time": Timestamp_str, "Type": "Beacon Flood", "Attacker": "Spoofed APs", "Target": "Broadcast", "Event": "Beacon Flood Started"})
                    Play_Audio_Debounced("Audio/Beacon_Start.mp3", "Beacon_Start")
                Active_Attacks["Beacon_Flood"] = {"Attacker": "Multiple Spoofed MACs", "Target": "Airwaves", "Rate": len(Recent_BSSIDs), "Last_Seen": Current_Time, "Status": "ACTIVE", "Type": "Beacon Flood"}
            else:
                if Beacon_Flood_Active and (Current_Time - Active_Attacks.get("Beacon_Flood", {}).get("Last_Seen", 0) >= 4.0):
                    Beacon_Flood_Active = False
                    if "Beacon_Flood" in Active_Attacks:
                        del Active_Attacks["Beacon_Flood"]
                    Attack_Logs.append({"Time": Timestamp_str, "Type": "Beacon Flood", "Attacker": "Spoofed APs", "Target": "Broadcast", "Event": "Beacon Flood Cleared"})
                    Play_Audio_Debounced("Audio/Beacon_Stop.mp3", "Beacon_Stop")

            active_rogues = 0
            for r_key, r_last_seen in list(Rogue_AP_Tracker.items()):
                if Current_Time - r_last_seen <= 4.0:
                    active_rogues += 1
                else:
                    if r_key in Active_Attacks:
                        del Active_Attacks[r_key]
                    del Rogue_AP_Tracker[r_key]

            if active_rogues == 0 and Rogue_AP_Active:
                Rogue_AP_Active = False
                Attack_Logs.append({"Time": Timestamp_str, "Type": "Rogue AP / Evil Twin", "Attacker": "Multiple", "Target": "Network Baseline", "Event": "Rogue AP Cleared"})
                Play_Audio_Debounced("Audio/Rogue_Stop.mp3", "Rogue_Stop")

            if len(Attack_Logs) > 8:
                Attack_Logs.pop(0)

def Packet_Processing_Worker():
    while Keep_Running:
        try:
            Item = Packet_Queue.get(timeout=0.5)
        except queue.Empty:
            continue

        Packet, Captured_Channel, Packet_Time = Item
        Timestamp_str = datetime.now().strftime("%H:%M:%S")

        if Packet.haslayer(Dot11):
            addr1 = Packet.addr1.lower() if Packet.addr1 else None
            addr2 = Packet.addr2.lower() if Packet.addr2 else None
            addr3 = Packet.addr3.lower() if Packet.addr3 else None
            
            with Tracker_Lock:
                for bssid in Network_Status:
                    if bssid in [addr1, addr2, addr3]:
                        if bssid not in AP_Clients:
                            AP_Clients[bssid] = {}
                        
                        for candidate in [addr1, addr2]:
                            if candidate and candidate != bssid and candidate not in ["ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"]:
                                AP_Clients[bssid][candidate] = Packet_Time

        if Packet.haslayer(Dot11Beacon) or Packet.haslayer(Dot11ProbeResp):
            BSSID = Get_BSSID_From_Packet(Packet)
            if BSSID:
                SSID = Get_SSID_From_Packet(Packet)
                dBm_Str = "N/A"
                if Packet.haslayer(RadioTap):
                    try:
                        dBm_Str = f"{int(Packet[RadioTap].dBm_AntSignal)} dBm"
                    except Exception:
                        pass

                with Tracker_Lock:
                    Seen_BSSIDs[BSSID] = Packet_Time
                    Evaluate_Dynamic_Baseline(BSSID, SSID, Timestamp_str, Packet_Time)
                    
                    if BSSID in Network_Status:
                        Network_Status[BSSID]["dBm"] = dBm_Str
                        Network_Status[BSSID]["Last_Seen"] = Packet_Time
                        if SSID != "Hidden" and Network_Status[BSSID]["SSID"] == "Hidden":
                            Network_Status[BSSID]["SSID"] = SSID
                    else:
                        channel = Captured_Channel
                        band = Get_Band_String(channel)
                        Network_Status[BSSID] = {
                            "SSID": SSID, "dBm": dBm_Str, 
                            "Channel": channel,"Band": band,"Last_Seen": Packet_Time
                        }

        if Packet.haslayer(Dot11Deauth) or Packet.haslayer(Dot11Disas):
            Source_MAC = Packet.addr2.lower() if Packet.addr2 else "Unknown"
            Target_MAC = Packet.addr1.lower() if Packet.addr1 else "Unknown"
            
            if Source_MAC not in ["ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"]:
                with Tracker_Lock:
                    Deauth_Packet_Log.append((Packet_Time, Source_MAC, Target_MAC, Captured_Channel))

        Packet_Queue.task_done()

def Format_Signal_Cell(dbm_String):
    if not dbm_String or dbm_String == "N/A":
        return Text("N/A", style="dim white")
    Match = re.search(r'(-\d+|\d+)', dbm_String)
    if not Match:
        return Text(dbm_String, style="dim white")
    dBm_Val = int(Match.group(1))
    
    if dBm_Val >= -60:
        return Text(dbm_String, style="bold green")
    elif -61 >= dBm_Val >= -75:
        return Text(dbm_String, style="bold yellow")
    else:
        return Text(dbm_String, style="bold red")

def Generate_Dashboard():
    Current_Time = time.time()
    
    with Tracker_Lock:
        if not Baseline_Completed:
            Baseline_Status = f"[LEARNING BASELINE: CYCLE {Completed_Cycles + 1}/{Baseline_Scan_Cycles} - CH {Current_Channel}]"
        else:
            Baseline_Status = f"[CHANNEL HOPPING - CH {Current_Channel}]"

        Attack_Table = Table(title=f"Live Threat Monitor {Baseline_Status}", expand=True)
        Attack_Table.add_column("Attack Vector", style="bold red")
        Attack_Table.add_column("Attacker Identity", style="cyan")
        Attack_Table.add_column("Target Identity", style="magenta")
        Attack_Table.add_column("Metrics", style="yellow")
        Attack_Table.add_column("Threat Status", style="bold")
    
        if not Baseline_Completed:
            Attack_Table.add_row("INITIALIZING", "Building Dynamic Map", "Scanning Spectrum", "Warmup", "[bold cyan]LEARNING BASELINE[/bold cyan]")
        elif not Active_Attacks:
            Attack_Table.add_row("None", "None", "None", "0 units/sec", "[green]SYSTEM SECURE[/green]")
        else:
            Grouped_Attacks = {}
            for Key, Info in Active_Attacks.items():
                atype = Info["Type"]
                if atype not in Grouped_Attacks:
                    Grouped_Attacks[atype] = {
                        "Attackers": set(),
                        "Targets": set(),
                        "Total_Rate": 0,
                        "Count": 0
                    }
                Grouped_Attacks[atype]["Attackers"].add(Info["Attacker"])
                Grouped_Attacks[atype]["Targets"].add(Info["Target"])
                Grouped_Attacks[atype]["Total_Rate"] += Info["Rate"]
                Grouped_Attacks[atype]["Count"] += 1

            for atype, summary in Grouped_Attacks.items():
                attacker_str = list(summary["Attackers"])[0] if summary["Count"] == 1 else f"Multiple ({len(summary['Attackers'])})"
                target_str = list(summary["Targets"])[0] if summary["Count"] == 1 else f"Multiple ({len(summary['Targets'])})"
                rate_str = f"{summary['Total_Rate']} pkts/sec" if "Deauth" in atype else f"{summary['Count']} Active"
                
                Status_Text = Text("ATTACK ACTIVE", style="blink bold red")
                Attack_Table.add_row(atype, attacker_str, target_str, rate_str, Status_Text)

        Net_Table = Table(title="Monitored Wi-Fi Infrastructure States", expand=True)
        Net_Table.add_column("BSSID", style="bold green")
        Net_Table.add_column("SSID", style="white")
        Net_Table.add_column("Channel", style="yellow")
        Net_Table.add_column("Band", style="magenta")
        Net_Table.add_column("Connected Clients", style="bold cyan")
        Net_Table.add_column("Signal Strength", style="bold")
        Net_Table.add_column("Operational State", style="bold")

        if not Network_Status:
            Net_Table.add_row("Scanning Interfaces...", "Scanning...", "N/A", "N/A", "0", "N/A", "Waiting for Beacons...")
        else:
            Sorted_Networks = sorted(Network_Status.items(), key=lambda x: x[1]["Last_Seen"], reverse=True)
            for BSSID, Info in Sorted_Networks[:10]:
                State = Text("Online / Active", style="bold green") if Current_Time - Info["Last_Seen"] <= 5.0 else Text("Online / Fading", style="dim yellow")
                Signal_Cell = Format_Signal_Cell(Info["dBm"])
                Channel_Cell = Text(str(Info.get("Channel", "N/A")), style="yellow")
                Band_Cell = Text(Info.get("Band", "Unknown"), style="magenta")
                
                active_client_count = 0
                if BSSID in AP_Clients:
                    active_clients = [c for c, ts in AP_Clients[BSSID].items() if Current_Time - ts <= 60.0]
                    active_client_count = len(active_clients)
                
                Net_Table.add_row(BSSID, Info["SSID"], Channel_Cell, Band_Cell, str(active_client_count), Signal_Cell, State)

        Log_Table = Table(title="Security Event History Log", expand=True)
        Log_Table.add_column("Timestamp", style="dim white")
        Log_Table.add_column("Attack Vector", style="bold red")
        Log_Table.add_column("Attacker Address/BSSID", style="cyan")
        Log_Table.add_column("Target Address/SSID", style="magenta")
        Log_Table.add_column("Incident Event State", style="yellow")

        if not Attack_Logs:
            Log_Table.add_row("-", "-", "-", "-", "No historic events recorded")
        else:
            for Entry in Attack_Logs:
                Log_Table.add_row(Entry["Time"], Entry["Type"], Entry["Attacker"], Entry["Target"], Entry["Event"])

    return Panel(
        Group(Attack_Table, Text(""), Net_Table, Text(""), Log_Table), 
        title="[bold cyan]Wave Watcher | Operation: Static Shift[/bold cyan]", 
        border_style="blue"
    )

def Enqueue_Packet(pkt):
    if Keep_Running:
        with Tracker_Lock:
            captured_channel = Current_Channel
        Packet_Queue.put((pkt, captured_channel, time.time()))

def WiFi_Monitor(WiFi_Interface):
    global Keep_Running
    
    threading.Thread(target=Audio_Playback_Worker, daemon=True).start()
    threading.Thread(target=Packet_Processing_Worker, daemon=True).start()
    Audio_Queue.put("Audio/Initializing.mp3")

    threading.Thread(target=Channel_Hopper, args=(WiFi_Interface,), daemon=True).start()
    threading.Thread(target=Alert_Evaluator, daemon=True).start()
    
    threading.Thread(
        target=lambda: sniff(iface=WiFi_Interface, prn=Enqueue_Packet, store=0, stop_filter=lambda p: not Keep_Running), 
        daemon=True
    ).start()

    print(f"{Success}Engine Active. Monitoring on {WiFi_Interface}")
    
    try:
        with Live(Generate_Dashboard(), refresh_per_second=4, screen=True) as Live_Status:
            while True:
                time.sleep(0.25)
                Live_Status.update(Generate_Dashboard())
    except KeyboardInterrupt:
        print(f"{Info}Stopping UI Display and Cleaning up Interfaces.")
        playsound("Audio/Stopping.mp3")
        Keep_Running = False  
        time.sleep(0.5)       

if __name__ == "__main__":
    if os.geteuid() != 0:
        print(f"{Error}Error: This Script Requires Root Privileges.")
        print(f"{Warning}Run Using 'sudo'.")
        playsound("Audio/Root Privileges.mp3")
        sys.exit(1)

    WiFi_Interfaces_List = Get_WiFi_Interfaces()
    print(Logo)
    print(f"{Info_2}Available WiFi Interfaces: {', '.join(WiFi_Interfaces_List)}")
    playsound("Audio/Enter Wi-Fi Interface.mp3")
    WiFi_Interface_Choosen = input(f"{Ask}Enter The Name Of The WiFi Interface: ").strip()
    
    if WiFi_Interface_Choosen not in WiFi_Interfaces_List:
        print(f"{Error}Error: Invalid Interface Selected.")
        playsound("Audio/Invalid Interface.mp3")
        sys.exit(1)

    Active_mon_Interface = Enable_Monitor_Mode(WiFi_Interface_Choosen)
    if Active_mon_Interface:
        try:
            WiFi_Monitor(Active_mon_Interface)
        finally:
            Disable_Monitor_Mode(Active_mon_Interface)