from v2x import MsgFrame

# decode
data = '00016626466686a6c6e700001246654268f3dc631a51400000001f91f91fdfffc00140140000'
msg = MsgFrame.MessageFrame
msg.from_uper(bytes.fromhex(data))
print(msg())

# encode
raw = ('bsmFrame',{'msgCnt': 11,'id':b'12345678','secMark':0,'pos': {'lat': -594657005, 'long': -598404839, 'elevation': 49802}, 'transmission':'neutral','speed':0,'heading':0,'accelSet':{'lat': 20, 'long': 20, 'vert':0,'yaw':0},'brakes':{} ,'size':{'width':20,'length':20},'vehicleClass':{'classification':0} })
payload  = MsgFrame.MessageFrame.to_uper(raw)
print(payload.hex())

assert(data == payload.hex())