from pwn import *
from asn.v2x import MsgFrame
import os
import random
import threading
#context(log_level='debug')

optional = lambda : random.randint(0,1)

def random_ascii(size):
    tmp = ""
    for i in range(size):
        tmp += chr(random.randint(0,126))
    return tmp

def gen_BSM():
    tmp = {}
    tmp['msgCnt']       =   random.randint(0,127)
    tmp['id']           =   os.urandom(8)
    tmp['secMark']      =   random.randint(0,65535)
    tmp['pos']          =   {'lat' : random.randint(-900000000,900000001),
                             'long': random.randint(-1799999999,1800000001)}
    tmp['transmission'] =   random.choice(['neutral', 'park', 'forwardGears','reverseGears',
                                           'reserved1','reserved2','reserved3','unavailable'])
    tmp['speed']        =   random.randint(0,8191)
    tmp['heading']      =   random.randint(0,240)
    tmp['accelSet']     =   {'lat' : random.randint(-2000,2001), 
                             'long': random.randint(-2000,2001), 
                             'vert': random.randint(-127,127), 
                             'yaw' : random.randint(-32767,32767)}
    tmp['brakes']       =   {}
    tmp['size']         =   {'width' : random.randint(0,1023),
                             'length': random.randint(0,4095)}
    tmp['vehicleClass'] =   {'classification': random.randint(0,255)}
    
    # --- OPTIONAL ---
    
    # elevation Elevation OPTIONAL
    if(optional()): tmp['pos']['elevation'] = random.randint(-4096,61439)

    # height VehicleHeight OPTIONAL
    if(optional()): tmp['size']['height']   = random.randint(0,127)
    
    # fuelType FuelType OPTIONAL
    if(optional()): tmp['vehicleClass']['fuelType'] = random.randint(0,15)
    
    # timeConfidence TimeConfidence OPTIONAL
    if(optional()): 
        tmp['timeConfidence'] = random.choice(['unavailable','time-100-000','time-050-000','time-020-000',
                                               'time-010-000','time-002-000','time-001-000','time-000-500',
                                               'time-000-200','time-000-100','time-000-050','time-000-020',
                                               'time-000-010','time-000-005','time-000-002','time-000-001',
                                               'time-000-000-5','time-000-000-2','time-000-000-1','time-000-000-05',
                                               'time-000-000-02','time-000-000-01','time-000-000-005','time-000-000-002',
                                               'time-000-000-001','time-000-000-000-5','time-000-000-000-2',
                                               'time-000-000-000-1','time-000-000-000-05','time-000-000-000-02',
                                               'time-000-000-000-01','time-000-000-000-005','time-000-000-000-002',
                                               'time-000-000-000-001','time-000-000-000-000-5','time-000-000-000-000-2',
                                               'time-000-000-000-000-1','time-000-000-000-000-05','time-000-000-000-000-02',
                                               'time-000-000-000-000-01'])
        
    # posAccuracy PositionalAccuracy OPTIONAL
    if(optional()): 
        tmp['posAccuracy'] = {'semiMajor': random.randint(0,255),
                              'semiMinor': random.randint(0,255),
                              'orientation':random.randint(0,65535)}
    
    # posConfidence PositionConfidenceSet OPTIONAL
    if(optional()): 
        tmp['posConfidence'] = {'pos': random.choice(['unavailable','a500m','a200m','a100m','a50m','a20m','a10m',
                                                      'a5m','a2m','a1m','a50cm','a20cm','a10cm','a5cm','a2cm','a1cm'])}
        if(optional()):
             tmp['posConfidence']['elevation'] = random.choice(['unavailable','elev-500-00','elev-200-00','elev-100-00',
                                                                'elev-050-00','elev-020-00','elev-010-00','elev-005-00',
                                                                'elev-002-00','elev-001-00','elev-000-50','elev-000-20',
                                                                'elev-000-10','elev-000-05','elev-000-02','elev-000-01'])
             
    # angle SteeringWheelAngle OPTIONAL
    if(optional()): tmp['angle'] = random.randint(-126,127)

    # motionCfd MotionConfidenceSet OPTIONAL
    if(optional()):
        tmp['motionCfd']={}
        if(optional()):
            tmp['motionCfd']['speedCfd']    = random.choice(['unavailable','prec100ms','prec10ms','prec5ms',
                                                             'prec1ms','prec0-1ms','prec0-05ms','prec0-01ms'])
        if(optional()):
            tmp['motionCfd']['headingCfd']  = random.choice(['unavailable','prec10deg','prec05deg','prec01deg',
                                                             'prec0-1deg', 'prec0-05deg','prec0-01deg','prec0-0125deg'])
        if(optional()):
            tmp['motionCfd']['steerCfd']    = random.choice(['unavailable','prec2deg','prec1deg','prec0-02deg'])
    
    # brakes BrakeSystemStatus
    if(optional()): tmp['brakes']['brakePadel']  = random.choice(['unavailable','off','on'])
    if(optional()): tmp['brakes']['wheelBrakes'] = (random.randint(0,31),5)
    if(optional()): tmp['brakes']['traction']    = random.choice(['unavailable','off','on','engaged'])
    if(optional()): tmp['brakes']['abs']         = random.choice(['unavailable','off','on','engaged'])
    if(optional()): tmp['brakes']['scs']         = random.choice(['unavailable','off','on','engaged'])
    if(optional()): tmp['brakes']['brakeBoost']  = random.choice(['unavailable','off','on'])
    if(optional()): tmp['brakes']['auxBrakes']   = random.choice(['unavailable','off','on','reserved'])
        
    
    # safetyExt VehicleSafetyExtensions OPTIONAL
    if(optional()): 
        tmp['safetyExt']  = {}
        if(optional()): 
            bit = random.randint(0,65536)
            tmp['safetyExt']['events'] = (random.randint(0,pow(2,bit)),bit)
        if(optional()): 
            bit = random.randint(0,65536)
            tmp['safetyExt']['lights'] = (random.randint(0,pow(2,bit)),bit)
        if(optional()): 
            tmp['safetyExt']['pathPrediction'] = {'radiusOfCurve': random.randint(-32767,32767),
                                                  'confidence'   : random.randint(0,200) }
        if(optional()): 
            tmp['safetyExt']['pathHistory'] = {}
            tmp['safetyExt']['pathHistory']['crumbData'] = []
            for i in range(random.randint(1,23)):
                tmp_PathHistoryPoint={}
                tmp_PathHistoryPoint['llvOffset']={}
                tmp_PathHistoryPoint['llvOffset']['offsetLL'] = random.choice([ ('position-LL1',{'lon':random.randint(-2048,2047),"lat":random.randint(-2048,2047)}),
                                                                                ('position-LL2',{'lon':random.randint(-8192,8191),"lat":random.randint(-8192,8191)}),
                                                                                ('position-LL3',{'lon':random.randint(-32768,32767),"lat":random.randint(-32768,32767)}),
                                                                                ('position-LL4',{'lon':random.randint(-131072,131071),"lat":random.randint(-131072,131071)}),
                                                                                ('position-LL5',{'lon':random.randint(-2097152,2097151),"lat":random.randint(-2097152,2097151)}),
                                                                                ('position-LL6',{'lon':random.randint(-8388608,8388607),"lat":random.randint(-8388608,8388607)}),
                                                                                ('position-LatLon',{'lon':random.randint(-1799999999,1800000001),"lat":random.randint(-900000000,900000001)}) ])
                tmp_PathHistoryPoint['timeOffset'] = random.randint(1,65535)
                
                if(optional()):
                    tmp_PathHistoryPoint['llvOffset']['offsetV'] = random.choice([ ('offset1',random.randint(-64,63)),
                                                                                   ('offset2',random.randint(-128,127)),
                                                                                   ('offset3',random.randint(-256,255)),
                                                                                   ('offset4',random.randint(-512,511)),
                                                                                   ('offset5',random.randint(-1024,1023)),
                                                                                   ('offset6',random.randint(-2048,2047)),
                                                                                   ('elevation',random.randint(-4096,61439)) ])
                if(optional()):
                    tmp_PathHistoryPoint['speed'] = random.randint(0,8191)
                
                if(optional()):
                    tmp_PathHistoryPoint['posAccuracy'] =  {'pos': random.choice(['unavailable','a500m','a200m','a100m','a50m','a20m','a10m',
                                                                                  'a5m','a2m','a1m','a50cm','a20cm','a10cm','a5cm','a2cm','a1cm'])}
                    if(optional()):
                        tmp_PathHistoryPoint['posAccuracy']['elevation'] = random.choice(['unavailable','elev-500-00','elev-200-00','elev-100-00',
                                                                                          'elev-050-00','elev-020-00','elev-010-00','elev-005-00',
                                                                                          'elev-002-00','elev-001-00','elev-000-50','elev-000-20',
                                                                                          'elev-000-10','elev-000-05','elev-000-02','elev-000-01'])
                    
                if(optional()):
                    tmp_PathHistoryPoint['heading'] = random.randint(0,240)
                
                
                tmp['safetyExt']['pathHistory']['crumbData'] += [tmp_PathHistoryPoint]
            
            # initialPosition FullPositionVector OPTIONAL
            if(optional()): 
                tmp['safetyExt']['pathHistory']['initialPosition'] = {}
                tmp['safetyExt']['pathHistory']['initialPosition']['pos'] = {'lat' : random.randint(-900000000,900000001),
                                                                             'long': random.randint(-1799999999,1800000001)}
                if(optional()): 
                    tmp['safetyExt']['pathHistory']['initialPosition']['pos']['elevation'] = random.randint(-4096,61439)
                
                if(optional()): 
                    tmp['safetyExt']['pathHistory']['initialPosition']['utcTime'] = {}
                    if(optional()): tmp['safetyExt']['pathHistory']['initialPosition']['utcTime']['year']   = random.randint(0,4095)
                    if(optional()): tmp['safetyExt']['pathHistory']['initialPosition']['utcTime']['month']  = random.randint(0,12)
                    if(optional()): tmp['safetyExt']['pathHistory']['initialPosition']['utcTime']['day']    = random.randint(0,31)
                    if(optional()): tmp['safetyExt']['pathHistory']['initialPosition']['utcTime']['hour']   = random.randint(0,31)
                    if(optional()): tmp['safetyExt']['pathHistory']['initialPosition']['utcTime']['minute'] = random.randint(0,60)
                    if(optional()): tmp['safetyExt']['pathHistory']['initialPosition']['utcTime']['second'] = random.randint(0,65535)
                    if(optional()): tmp['safetyExt']['pathHistory']['initialPosition']['utcTime']['offset'] = random.randint(-840,840)
                    
                if(optional()):
                    tmp['safetyExt']['pathHistory']['initialPosition']['heading'] = random.randint(0,28800)
                
                if(optional()):
                    tmp['safetyExt']['pathHistory']['initialPosition']['transmission'] = random.choice(['neutral', 'park', 'forwardGears','reverseGears',
                                                                                                        'reserved1','reserved2','reserved3','unavailable'])
                if(optional()):
                    tmp['safetyExt']['pathHistory']['initialPosition']['speed'] = random.randint(0,8191)
                    
                if(optional()):
                    tmp['safetyExt']['pathHistory']['initialPosition']['posAccuracy'] = {'pos': random.choice(['unavailable','a500m','a200m','a100m','a50m','a20m','a10m',
                                                                                                               'a5m','a2m','a1m','a50cm','a20cm','a10cm','a5cm','a2cm','a1cm'])}
                    if(optional()):
                        tmp['safetyExt']['pathHistory']['initialPosition']['posAccuracy']['elevation'] = random.choice(['unavailable','elev-500-00','elev-200-00','elev-100-00',
                                                                                                                         'elev-050-00','elev-020-00','elev-010-00','elev-005-00',
                                                                                                                         'elev-002-00','elev-001-00','elev-000-50','elev-000-20',
                                                                                                                         'elev-000-10','elev-000-05','elev-000-02','elev-000-01'])
                if(optional()):
                    tmp['safetyExt']['pathHistory']['initialPosition']['timeConfidence'] = random.choice(['unavailable','time-100-000','time-050-000','time-020-000',
                                                                                                          'time-010-000','time-002-000','time-001-000','time-000-500',
                                                                                                          'time-000-200','time-000-100','time-000-050','time-000-020',
                                                                                                          'time-000-010','time-000-005','time-000-002','time-000-001',
                                                                                                          'time-000-000-5','time-000-000-2','time-000-000-1','time-000-000-05',
                                                                                                          'time-000-000-02','time-000-000-01','time-000-000-005','time-000-000-002',
                                                                                                          'time-000-000-001','time-000-000-000-5','time-000-000-000-2',
                                                                                                          'time-000-000-000-1','time-000-000-000-05','time-000-000-000-02',
                                                                                                          'time-000-000-000-01','time-000-000-000-005','time-000-000-000-002',
                                                                                                          'time-000-000-000-001','time-000-000-000-000-5','time-000-000-000-000-2',
                                                                                                          'time-000-000-000-000-1','time-000-000-000-000-05','time-000-000-000-000-02',
                                                                                                          'time-000-000-000-000-01'])
                if(optional()):
                    tmp['safetyExt']['pathHistory']['initialPosition']['motionCfd'] = {}
                    
                    if(optional()):
                        tmp['safetyExt']['pathHistory']['initialPosition']['motionCfd']['speedCfd']    = random.choice(['unavailable','prec100ms','prec10ms','prec5ms',
                                                                                                                        'prec1ms','prec0-1ms','prec0-05ms','prec0-01ms'])
                    if(optional()):
                        tmp['safetyExt']['pathHistory']['initialPosition']['motionCfd']['headingCfd']  = random.choice(['unavailable','prec10deg','prec05deg','prec01deg',
                                                                                                                        'prec0-1deg', 'prec0-05deg','prec0-01deg','prec0-0125deg'])
                    if(optional()):
                        tmp['safetyExt']['pathHistory']['initialPosition']['motionCfd']['steerCfd']    = random.choice(['unavailable','prec2deg','prec1deg','prec0-02deg'])
                        
                    
                    
            # currGNSSstatus GNSSstatus OPTIONAL
            if(optional()): 
                tmp['safetyExt']['pathHistory']['currGNSSstatus'] = (random.randint(0,pow(2,8)),8)
                
    # emergencyExt VehicleEmergencyExtensions OPTIONAL
    if(optional()):
        tmp['emergencyExt']  = {}
        if(optional()): tmp['emergencyExt']['responseType']   = random.choice(['notInUseOrNotEquipped','emergency','nonEmergency',
                                                                               'pursuit','stationary','slowMoving','stopAndGoMovement'])
        if(optional()): tmp['emergencyExt']['sirenUse']       = random.choice(['unavailable','notInUse','inUse','reserved'])
        if(optional()): tmp['emergencyExt']['lightsUse']      = random.choice(['unavailable','notInUse','inUse','yellowCautionLights',
                                                                               'schooldBusLights','arrowSignsActive','slowMovingVehicle','freqStops'])
    
    raw = ('bsmFrame',tmp)
    return raw

def gen_SPAT():
    tmp = {}
    tmp['msgCnt']  =  random.randint(0,127)
    tmp['intersections'] = []
    
    for i in range(random.randint(1,32)):
        tmp_IntersectionState = {}
        tmp_IntersectionState['intersectionId'] = {'id': random.randint(0,65535)}
        tmp_IntersectionState['status'] = (random.randint(0,pow(2,16)),16)
        
        # --- PART OPTIONAL BEGIN ---
        if(optional()): tmp_IntersectionState['intersectionId']['region'] =  random.randint(0,65535)
        if(optional()): tmp_IntersectionState['moy']            =  random.randint(0,527040)
        if(optional()): tmp_IntersectionState['timeStamp']      =  random.randint(0,65535)
        if(optional()): tmp_IntersectionState['timeConfidence'] =  random.choice(['unavailable','time-100-000','time-050-000','time-020-000',
                                                                                  'time-010-000','time-002-000','time-001-000','time-000-500',
                                                                                  'time-000-200','time-000-100','time-000-050','time-000-020',
                                                                                  'time-000-010','time-000-005','time-000-002','time-000-001',
                                                                                  'time-000-000-5','time-000-000-2','time-000-000-1','time-000-000-05',
                                                                                  'time-000-000-02','time-000-000-01','time-000-000-005','time-000-000-002',
                                                                                  'time-000-000-001','time-000-000-000-5','time-000-000-000-2',
                                                                                  'time-000-000-000-1','time-000-000-000-05','time-000-000-000-02',
                                                                                  'time-000-000-000-01','time-000-000-000-005','time-000-000-000-002',
                                                                                  'time-000-000-000-001','time-000-000-000-000-5','time-000-000-000-000-2',
                                                                                  'time-000-000-000-000-1','time-000-000-000-000-05','time-000-000-000-000-02',
                                                                                  'time-000-000-000-000-01'])
        # --- PART OPTIONAL END ---
        
        tmp_IntersectionState['phases'] = []
        for j in range(random.randint(1,16)):
            tmp_Phase = {}
            tmp_Phase['id'] = random.randint(0,255)
            tmp_Phase['phaseStates'] = []
            for k in range(random.randint(1,16)):
                tmp_PhaseState = {}
                tmp_PhaseState['light'] = random.choice(['unavailable', 'dark', 'flashing-red','red','flashing-green',
                                                         'permissive-green','protected-green','yellow','flashing-yellow'])
                
                # timing TimeChangeDetails OPTIONAL
                if(optional()): 
                    tmp_counting = {'startTime':random.randint(0,36001),'likelyEndTime':random.randint(0,36001)}
                    if(optional()): tmp_counting['minEndTime']     = random.randint(0,36001)
                    if(optional()): tmp_counting['maxEndTime']     = random.randint(0,36001)
                    if(optional()): tmp_counting['timeConfidence'] = random.randint(0,200)
                    if(optional()): tmp_counting['nextStartTime']  = random.randint(0,36001)
                    if(optional()): tmp_counting['nextDuration']   = random.randint(0,36001)
                    
                    tmp_utcTiming = {'startUTCTime':random.randint(0,36001),'likelyEndUTCTime':random.randint(0,36001)}
                    if(optional()): tmp_utcTiming['minEndUTCTime']     = random.randint(0,36001)
                    if(optional()): tmp_utcTiming['maxEndUTCTime']     = random.randint(0,36001)
                    if(optional()): tmp_utcTiming['timeConfidence']    = random.randint(0,200)
                    if(optional()): tmp_utcTiming['nextStartUTCTime']  = random.randint(0,36001)
                    if(optional()): tmp_utcTiming['nextEndUTCTime']    = random.randint(0,36001)

                    tmp_PhaseState['timing'] = random.choice([ ('counting',tmp_counting), ('utcTiming',tmp_utcTiming)])
                
                tmp_Phase['phaseStates'] += [tmp_PhaseState]
                
            tmp_IntersectionState['phases'] += [tmp_Phase]
    
    tmp['intersections'] += [tmp_IntersectionState]
    
    # --- OPTIONAL ---
    # moy MinuteOfTheYear OPTIONAL
    if(optional()): tmp['moy'] = random.randint(0,527040)
    
    # timeStamp DSecond OPTIONAL
    if(optional()): tmp['timeStamp'] = random.randint(0,65535)
    
    # name DescriptiveName OPTIONAL
    if(optional()): tmp['name'] = random_ascii(random.randint(1,63))

    raw = ('spatFrame',tmp)
    return raw

def gen_RSM():
    tmp = {}
    tmp['msgCnt']  =  random.randint(0,127)
    tmp['id']      =  os.urandom(8)
    tmp['refPos']  =  {'lat' : random.randint(-900000000,900000001),
                       'long': random.randint(-1799999999,1800000001)}
    
    if(optional()): tmp['refPos']['elevation'] = random.randint(-4096,61439)
    
    tmp['participants']  = []
    for i in range(random.randint(1,16)):
        tmp_ParticipantData = {}
        tmp_ParticipantData['ptcType'] =  random.choice(['unknown', 'motor', 'non-motor','pedestrian','rsu'])
        tmp_ParticipantData['ptcId']   =  random.randint(0,65535)
        tmp_ParticipantData['source']  =  random.choice(['unknown', 'selfinfo', 'v2x','video','microwaveRadar','loop','lidar','integrated'])
        tmp_ParticipantData['secMark'] =  random.randint(0,65535)
        
        tmp_ParticipantData['pos']     =  {}
        tmp_ParticipantData['pos']['offsetLL'] = random.choice([ ('position-LL1',{'lon':random.randint(-2048,2047),"lat":random.randint(-2048,2047)}),
                                                                 ('position-LL2',{'lon':random.randint(-8192,8191),"lat":random.randint(-8192,8191)}),
                                                                 ('position-LL3',{'lon':random.randint(-32768,32767),"lat":random.randint(-32768,32767)}),
                                                                 ('position-LL4',{'lon':random.randint(-131072,131071),"lat":random.randint(-131072,131071)}),
                                                                 ('position-LL5',{'lon':random.randint(-2097152,2097151),"lat":random.randint(-2097152,2097151)}),
                                                                 ('position-LL6',{'lon':random.randint(-8388608,8388607),"lat":random.randint(-8388608,8388607)}),
                                                                 ('position-LatLon',{'lon':random.randint(-1799999999,1800000001),"lat":random.randint(-900000000,900000001)}) ])
        
        
        if(optional()):
            tmp_ParticipantData['pos']['offsetV'] = random.choice([ ('offset1',random.randint(-64,63)),
                                                                    ('offset2',random.randint(-128,127)),
                                                                    ('offset3',random.randint(-256,255)),
                                                                    ('offset4',random.randint(-512,511)),
                                                                    ('offset5',random.randint(-1024,1023)),
                                                                    ('offset6',random.randint(-2048,2047)),
                                                                    ('elevation',random.randint(-4096,61439)) ])
        tmp_ParticipantData['posConfidence']  =  {}
        tmp_ParticipantData['posConfidence']['pos']  = random.choice(['unavailable','a500m','a200m','a100m','a50m','a20m','a10m',
                                                                      'a5m','a2m','a1m','a50cm','a20cm','a10cm','a5cm','a2cm','a1cm'])
        
        if(optional()):
            tmp_ParticipantData['posConfidence']['elevation'] = random.choice(['unavailable','elev-500-00','elev-200-00','elev-100-00',
                                                                               'elev-050-00','elev-020-00','elev-010-00','elev-005-00',
                                                                               'elev-002-00','elev-001-00','elev-000-50','elev-000-20',
                                                                               'elev-000-10','elev-000-05','elev-000-02','elev-000-01'])
        tmp_ParticipantData['speed']    =  random.randint(0,8191)
        tmp_ParticipantData['heading']  =  random.randint(0,240)
        tmp_ParticipantData['size']     = {'width' : random.randint(0,1023),
                                           'length': random.randint(0,4095)}
        
        if(optional()): tmp_ParticipantData['size']['height']   = random.randint(0,127)
        
        # --- OPTIONAL ---
        # id OCTET STRING (SIZE(8)) OPTIONAL
        if(optional()): tmp_ParticipantData['id'] = os.urandom(8)
        
        # transmission TransmissionState OPTIONAL
        if(optional()): 
            tmp_ParticipantData['transmission'] = random.choice(['neutral', 'park', 'forwardGears','reverseGears',
                                                                 'reserved1','reserved2','reserved3','unavailable'])
        
        # angle SteeringWheelAngle OPTIONAL
        if(optional()): tmp_ParticipantData['angle'] = random.randint(-126,127)
        
        # motionCfd MotionConfidenceSet OPTIONAL
        if(optional()):
            tmp_ParticipantData['motionCfd']={}
            if(optional()):
                tmp_ParticipantData['motionCfd']['speedCfd']    = random.choice(['unavailable','prec100ms','prec10ms','prec5ms',
                                                                'prec1ms','prec0-1ms','prec0-05ms','prec0-01ms'])
            if(optional()):
                tmp_ParticipantData['motionCfd']['headingCfd']  = random.choice(['unavailable','prec10deg','prec05deg','prec01deg',
                                                                'prec0-1deg', 'prec0-05deg','prec0-01deg','prec0-0125deg'])
            if(optional()):
                tmp_ParticipantData['motionCfd']['steerCfd']    = random.choice(['unavailable','prec2deg','prec1deg','prec0-02deg'])
        
        # accelSet AccelerationSet4Way OPTIONAL
        if(optional()): 
            tmp_ParticipantData['accelSet'] = {'lat' : random.randint(-2000,2001), 
                                               'long': random.randint(-2000,2001), 
                                               'vert': random.randint(-127,127), 
                                               'yaw' : random.randint(-32767,32767)}
        
        # vehicleClass VehicleClassification OPTIONAL
        if(optional()): 
            tmp_ParticipantData['vehicleClass']  =  {'classification': random.randint(0,255)}
            if(optional()): 
                tmp_ParticipantData['vehicleClass']['fuelType'] = random.randint(0,15)
                
        tmp['participants'] += [tmp_ParticipantData]
    
    raw = ('rsmFrame',tmp)
    return raw

def gen_RSI():
    tmp = {}
    tmp['msgCnt']  =  random.randint(0,127)
    tmp['id']      =  os.urandom(8)
    tmp['refPos']  =  {'lat' : random.randint(-900000000,900000001),
                       'long': random.randint(-1799999999,1800000001)}
    
    # --- OPTIONAL ---
    # elevation Elevation OPTIONAL
    if(optional()): tmp['refPos']['elevation'] = random.randint(-4096,61439)
    
    # moy MinuteOfTheYear OPTIONAL
    if(optional()): tmp['moy']  = random.randint(0,527040)
    
    # rtes RTEList OPTIONAL
    if(optional()): 
        tmp['rtes'] = []
        for i in range(random.randint(1,8)):
            tmp_RTEData = {}
            tmp_RTEData['rteId']       = random.randint(0,255)
            tmp_RTEData['eventType']   = random.randint(0,65535)
            tmp_RTEData['eventSource'] = random.choice(['unknown','police', 'government','meteorological','internet','detection'])
            
            
            if(optional()): 
                tmp_RTEData['eventPos'] = {}
                tmp_RTEData['eventPos']['offsetLL'] = random.choice([ ('position-LL1',{'lon':random.randint(-2048,2047),"lat":random.randint(-2048,2047)}),
                                                                      ('position-LL2',{'lon':random.randint(-8192,8191),"lat":random.randint(-8192,8191)}),
                                                                      ('position-LL3',{'lon':random.randint(-32768,32767),"lat":random.randint(-32768,32767)}),
                                                                      ('position-LL4',{'lon':random.randint(-131072,131071),"lat":random.randint(-131072,131071)}),
                                                                      ('position-LL5',{'lon':random.randint(-2097152,2097151),"lat":random.randint(-2097152,2097151)}),
                                                                      ('position-LL6',{'lon':random.randint(-8388608,8388607),"lat":random.randint(-8388608,8388607)}),
                                                                      ('position-LatLon',{'lon':random.randint(-1799999999,1800000001),"lat":random.randint(-900000000,900000001)}) ])
            
                if(optional()):
                    tmp_RTEData['eventPos']['offsetV'] = random.choice([ ('offset1',random.randint(-64,63)),
                                                                         ('offset2',random.randint(-128,127)),
                                                                         ('offset3',random.randint(-256,255)),
                                                                         ('offset4',random.randint(-512,511)),
                                                                         ('offset5',random.randint(-1024,1023)),
                                                                         ('offset6',random.randint(-2048,2047)),
                                                                         ('elevation',random.randint(-4096,61439)) ])
            
            if(optional()): tmp_RTEData['eventRadius'] = random.randint(0,65535)
            if(optional()): tmp_RTEData['description'] = random.choice([ ('textGB2312',os.urandom(random.randint(2,512))), ('textString',random_ascii(random.randint(1,512))) ])
            if(optional()): 
                tmp_RTEData['timeDetails'] = {}
                if(optional()): tmp_RTEData['timeDetails']['startTime'] = random.randint(0,527040)
                if(optional()): tmp_RTEData['timeDetails']['endTime']   = random.randint(0,527040)
                if(optional()): tmp_RTEData['timeDetails']['endTimeConfidence'] =  random.choice(['unavailable','time-100-000','time-050-000','time-020-000',
                                                                                                  'time-010-000','time-002-000','time-001-000','time-000-500',
                                                                                                  'time-000-200','time-000-100','time-000-050','time-000-020',
                                                                                                  'time-000-010','time-000-005','time-000-002','time-000-001',
                                                                                                  'time-000-000-5','time-000-000-2','time-000-000-1','time-000-000-05',
                                                                                                  'time-000-000-02','time-000-000-01','time-000-000-005','time-000-000-002',
                                                                                                  'time-000-000-001','time-000-000-000-5','time-000-000-000-2',
                                                                                                  'time-000-000-000-1','time-000-000-000-05','time-000-000-000-02',
                                                                                                  'time-000-000-000-01','time-000-000-000-005','time-000-000-000-002',
                                                                                                  'time-000-000-000-001','time-000-000-000-000-5','time-000-000-000-000-2',
                                                                                                  'time-000-000-000-000-1','time-000-000-000-000-05','time-000-000-000-000-02',
                                                                                                  'time-000-000-000-000-01'])
            
            if(optional()): tmp_RTEData['priority']        = os.urandom(1)
            if(optional()): tmp_RTEData['eventConfidence'] = random.randint(0,200)
            
            if(optional()): 
                tmp_RTEData['referencePaths'] = []
                for i in range(random.randint(1,8)):
                    tmp_ReferencePath = {}
                    tmp_ReferencePath['pathRadius'] = random.randint(0,65535)
                    tmp_ReferencePath['activePath'] = []
                    for j in range(random.randint(2,32)):
                        tmp_PositionOffsetLLV = {}
                        tmp_PositionOffsetLLV['offsetLL'] = random.choice([ ('position-LL1',{'lon':random.randint(-2048,2047),"lat":random.randint(-2048,2047)}),
                                                                            ('position-LL2',{'lon':random.randint(-8192,8191),"lat":random.randint(-8192,8191)}),
                                                                            ('position-LL3',{'lon':random.randint(-32768,32767),"lat":random.randint(-32768,32767)}),
                                                                            ('position-LL4',{'lon':random.randint(-131072,131071),"lat":random.randint(-131072,131071)}),
                                                                            ('position-LL5',{'lon':random.randint(-2097152,2097151),"lat":random.randint(-2097152,2097151)}),
                                                                            ('position-LL6',{'lon':random.randint(-8388608,8388607),"lat":random.randint(-8388608,8388607)}),
                                                                            ('position-LatLon',{'lon':random.randint(-1799999999,1800000001),"lat":random.randint(-900000000,900000001)}) ])
                        if(optional()):
                            tmp_PositionOffsetLLV['offsetV'] = random.choice([ ('offset1',random.randint(-64,63)),
                                                                         ('offset2',random.randint(-128,127)),
                                                                         ('offset3',random.randint(-256,255)),
                                                                         ('offset4',random.randint(-512,511)),
                                                                         ('offset5',random.randint(-1024,1023)),
                                                                         ('offset6',random.randint(-2048,2047)),
                                                                         ('elevation',random.randint(-4096,61439)) ])
                        tmp_ReferencePath['activePath'] += [tmp_PositionOffsetLLV]
                    
                    tmp_RTEData['referencePaths'] += [tmp_ReferencePath]    
                    
            
            if(optional()): 
                tmp_RTEData['referenceLinks'] = []
                for i in range(random.randint(1,16)):
                    tmp_ReferenceLink = {}
                    tmp_ReferenceLink['upstreamNodeId']   = {'id':random.randint(0,65535)}
                    tmp_ReferenceLink['downstreamNodeId'] = {'id':random.randint(0,65535)}
                    if(optional()): tmp_ReferenceLink['upstreamNodeId']['region']   = random.randint(0,65535)
                    if(optional()): tmp_ReferenceLink['downstreamNodeId']['region'] = random.randint(0,65535)
                    if(optional()): tmp_ReferenceLink['referenceLanes'] = (random.randint(0,pow(2,16)),16)
                    tmp_RTEData['referenceLinks'] += [tmp_ReferenceLink]
            
            tmp['rtes'] += [tmp_RTEData]
        
    # rtss RTSList OPTIONAL
    if(optional()): 
        tmp['rtss'] = []
        for i in range(random.randint(1,16)):
            tmp_RTSData = {}
            tmp_RTSData['rtsId']    = random.randint(0,255)
            tmp_RTSData['signType'] = random.randint(0,65535)
            
            if(optional()): 
                tmp_RTSData['signPos'] = {}
                tmp_RTSData['signPos']['offsetLL'] = random.choice([ ('position-LL1',{'lon':random.randint(-2048,2047),"lat":random.randint(-2048,2047)}),
                                                                     ('position-LL2',{'lon':random.randint(-8192,8191),"lat":random.randint(-8192,8191)}),
                                                                     ('position-LL3',{'lon':random.randint(-32768,32767),"lat":random.randint(-32768,32767)}),
                                                                     ('position-LL4',{'lon':random.randint(-131072,131071),"lat":random.randint(-131072,131071)}),
                                                                     ('position-LL5',{'lon':random.randint(-2097152,2097151),"lat":random.randint(-2097152,2097151)}),
                                                                     ('position-LL6',{'lon':random.randint(-8388608,8388607),"lat":random.randint(-8388608,8388607)}),
                                                                     ('position-LatLon',{'lon':random.randint(-1799999999,1800000001),"lat":random.randint(-900000000,900000001)}) ])
                if(optional()):
                    tmp_RTSData['signPos']['offsetV'] = random.choice([  ('offset1',random.randint(-64,63)),
                                                                         ('offset2',random.randint(-128,127)),
                                                                         ('offset3',random.randint(-256,255)),
                                                                         ('offset4',random.randint(-512,511)),
                                                                         ('offset5',random.randint(-1024,1023)),
                                                                         ('offset6',random.randint(-2048,2047)),
                                                                         ('elevation',random.randint(-4096,61439)) ])
                    
            if(optional()): tmp_RTSData['description'] = random.choice([ ('textGB2312',os.urandom(random.randint(2,512))), ('textString',random_ascii(random.randint(1,512))) ])
            if(optional()): 
                tmp_RTSData['timeDetails'] = {}
                if(optional()): tmp_RTSData['timeDetails']['startTime'] = random.randint(0,527040)
                if(optional()): tmp_RTSData['timeDetails']['endTime']   = random.randint(0,527040)
                if(optional()): tmp_RTSData['timeDetails']['endTimeConfidence'] =  random.choice(['unavailable','time-100-000','time-050-000','time-020-000',
                                                                                                'time-010-000','time-002-000','time-001-000','time-000-500',
                                                                                                'time-000-200','time-000-100','time-000-050','time-000-020',
                                                                                                'time-000-010','time-000-005','time-000-002','time-000-001',
                                                                                                'time-000-000-5','time-000-000-2','time-000-000-1','time-000-000-05',
                                                                                                'time-000-000-02','time-000-000-01','time-000-000-005','time-000-000-002',
                                                                                                'time-000-000-001','time-000-000-000-5','time-000-000-000-2',
                                                                                                'time-000-000-000-1','time-000-000-000-05','time-000-000-000-02',
                                                                                                'time-000-000-000-01','time-000-000-000-005','time-000-000-000-002',
                                                                                                'time-000-000-000-001','time-000-000-000-000-5','time-000-000-000-000-2',
                                                                                                'time-000-000-000-000-1','time-000-000-000-000-05','time-000-000-000-000-02',
                                                                                                'time-000-000-000-000-01'])
            if(optional()): tmp_RTSData['priority'] = os.urandom(1)
            
            if(optional()): 
                tmp_RTSData['referencePaths'] = []
                for i in range(random.randint(1,8)):
                    tmp_ReferencePath = {}
                    tmp_ReferencePath['pathRadius'] = random.randint(0,65535)
                    tmp_ReferencePath['activePath'] = []
                    for j in range(random.randint(2,32)):
                        tmp_PositionOffsetLLV = {}
                        tmp_PositionOffsetLLV['offsetLL'] = random.choice([ ('position-LL1',{'lon':random.randint(-2048,2047),"lat":random.randint(-2048,2047)}),
                                                                            ('position-LL2',{'lon':random.randint(-8192,8191),"lat":random.randint(-8192,8191)}),
                                                                            ('position-LL3',{'lon':random.randint(-32768,32767),"lat":random.randint(-32768,32767)}),
                                                                            ('position-LL4',{'lon':random.randint(-131072,131071),"lat":random.randint(-131072,131071)}),
                                                                            ('position-LL5',{'lon':random.randint(-2097152,2097151),"lat":random.randint(-2097152,2097151)}),
                                                                            ('position-LL6',{'lon':random.randint(-8388608,8388607),"lat":random.randint(-8388608,8388607)}),
                                                                            ('position-LatLon',{'lon':random.randint(-1799999999,1800000001),"lat":random.randint(-900000000,900000001)}) ])
                        if(optional()):
                            tmp_PositionOffsetLLV['offsetV'] = random.choice([ ('offset1',random.randint(-64,63)),
                                                                        ('offset2',random.randint(-128,127)),
                                                                        ('offset3',random.randint(-256,255)),
                                                                        ('offset4',random.randint(-512,511)),
                                                                        ('offset5',random.randint(-1024,1023)),
                                                                        ('offset6',random.randint(-2048,2047)),
                                                                        ('elevation',random.randint(-4096,61439)) ])
                        tmp_ReferencePath['activePath'] += [tmp_PositionOffsetLLV]
                    
                    tmp_RTSData['referencePaths'] += [tmp_ReferencePath]    
                
        
            if(optional()): 
                tmp_RTSData['referenceLinks'] = []
                for i in range(random.randint(1,16)):
                    tmp_ReferenceLink = {}
                    tmp_ReferenceLink['upstreamNodeId']   = {'id':random.randint(0,65535)}
                    tmp_ReferenceLink['downstreamNodeId'] = {'id':random.randint(0,65535)}
                    if(optional()): tmp_ReferenceLink['upstreamNodeId']['region']   = random.randint(0,65535)
                    if(optional()): tmp_ReferenceLink['downstreamNodeId']['region'] = random.randint(0,65535)
                    if(optional()): tmp_ReferenceLink['referenceLanes'] = (random.randint(0,pow(2,16)),16)
                    tmp_RTSData['referenceLinks'] += [tmp_ReferenceLink]
                
            
        tmp['rtss'] += [tmp_RTSData]
            
    raw = ('rsiFrame',tmp)
    return raw

def gen_MAP():
    tmp = {}
    tmp['msgCnt'] =  random.randint(0,127)
    tmp['nodes']  = []
    
    # max 32
    for i in range(random.randint(1,4)):
        tmp_Node = {}
        tmp_Node['id'] = {'id':random.randint(0,65535)}
        tmp_Node['refPos'] = {'lat' : random.randint(-900000000,900000001),
                              'long': random.randint(-1799999999,1800000001)}
        
        
        # --- OPTIONAL ---
        if(optional()): tmp_Node['id']['region']        = random.randint(0,65535)
        if(optional()): tmp_Node['refPos']['elevation'] = random.randint(-4096,61439)
        
        # name DescriptiveName OPTIONAL
        if(optional()): tmp_Node['name'] = random_ascii(random.randint(1,63))
        
        # inLinks LinkList OPTIONAL
        if(optional()): 
            tmp_Node['inLinks'] = []
            # max 32
            for j in range(random.randint(1,4)):
                tmp_Link = {}
                tmp_Link['upstreamNodeId']  = {'id':random.randint(0,65535)}
                tmp_Link['linkWidth']       = random.randint(0,32767)
                tmp_Link['lanes'] = []
                
                if(optional()): tmp_Link['upstreamNodeId']['region'] = random.randint(0,65535)
                if(optional()): tmp_Link['name']         =  random_ascii(random.randint(1,63))
                
                if(optional()): 
                    tmp_Link['speedLimits']  =  []
                    # max 9
                    for ii in range(random.randint(1,9)):
                        tmp_RegulatorySpeedLimit = {}
                        tmp_RegulatorySpeedLimit['type']  = random.choice(['unknown', 'maxSpeedInSchoolZone', 'maxSpeedInSchoolZoneWhenChildrenArePresent',
                                                                           'maxSpeedInConstructionZone','vehicleMinSpeed','vehicleMaxSpeed','vehicleNightMaxSpeed',
                                                                           'truckMinSpeed','truckMaxSpeed','truckNightMaxSpeed','vehiclesWithTrailersMinSpeed',
                                                                           'vehiclesWithTrailersMaxSpeed','vehiclesWithTrailersNightMaxSpeed'])
                        tmp_RegulatorySpeedLimit['speed'] = random.randint(0,8191)
                        
                        tmp_Link['speedLimits'] += [tmp_RegulatorySpeedLimit]
                
                if(optional()):
                    tmp_Link['points']  =  []
                    # max 31
                    for jj in range(random.randint(2,4)):
                        tmp_RoadPoint = {}
                        tmp_RoadPoint['posOffset'] = {}
                        tmp_RoadPoint['posOffset']['offsetLL'] = random.choice([ ('position-LL1',{'lon':random.randint(-2048,2047),"lat":random.randint(-2048,2047)}),
                                                                                 ('position-LL2',{'lon':random.randint(-8192,8191),"lat":random.randint(-8192,8191)}),
                                                                                 ('position-LL3',{'lon':random.randint(-32768,32767),"lat":random.randint(-32768,32767)}),
                                                                                 ('position-LL4',{'lon':random.randint(-131072,131071),"lat":random.randint(-131072,131071)}),
                                                                                 ('position-LL5',{'lon':random.randint(-2097152,2097151),"lat":random.randint(-2097152,2097151)}),
                                                                                 ('position-LL6',{'lon':random.randint(-8388608,8388607),"lat":random.randint(-8388608,8388607)}),
                                                                                 ('position-LatLon',{'lon':random.randint(-1799999999,1800000001),"lat":random.randint(-900000000,900000001)}) ])
                        if(optional()):
                            tmp_RoadPoint['posOffset']['offsetV'] = random.choice([ ('offset1',random.randint(-64,63)),
                                                                                    ('offset2',random.randint(-128,127)),
                                                                                    ('offset3',random.randint(-256,255)),
                                                                                    ('offset4',random.randint(-512,511)),
                                                                                    ('offset5',random.randint(-1024,1023)),
                                                                                    ('offset6',random.randint(-2048,2047)),
                                                                                    ('elevation',random.randint(-4096,61439)) ])
                        tmp_Link['points'] += [tmp_RoadPoint]
                
                if(optional()):
                    tmp_Link['movements']  = []
                    # max 31
                    for kk in range(random.randint(1,4)):
                        tmp_Movement = {}
                        tmp_Movement['remoteIntersection'] = {'id':random.randint(0,65535)}
                        if(optional()): tmp_Movement['remoteIntersection']['region'] = random.randint(0,65535)
                        if(optional()): tmp_Movement['phaseId'] = random.randint(0,255)
                        
                        tmp_Link['movements'] += [tmp_Movement]
                
                # max 32
                for k in range(random.randint(1,4)):
                    tmp_Lane = {}
                    tmp_Lane['laneID'] = random.randint(0,255)
                    
                    if(optional()): tmp_Lane['laneWidth'] = random.randint(0,32767)
                    
                    if(optional()): 
                        tmp_Lane['laneAttributes'] = {}
                        
                        bit = random.randint(0,65536)
                        tmp_Lane['laneAttributes']['laneType'] = random.choice([ ('vehicle',(random.randint(0,pow(2,bit)),bit)),
                                                                                 ('crosswalk',(random.randint(0,pow(2,16)),16)),
                                                                                 ('bikeLane',(random.randint(0,pow(2,16)),16)),
                                                                                 ('sidewalk',(random.randint(0,pow(2,16)),16)),
                                                                                 ('median',(random.randint(0,pow(2,16)),16)),
                                                                                 ('striping',(random.randint(0,pow(2,16)),16)),
                                                                                 ('trackedVehicle',(random.randint(0,pow(2,16)),16)),
                                                                                 ('parking',(random.randint(0,pow(2,16)),16)) ])
                        if(optional()):
                            tmp_Lane['laneAttributes']['shareWith'] = (random.randint(0,pow(2,10)),10)
                    
                    if(optional()): tmp_Lane['maneuvers'] = (random.randint(0,pow(2,12)),12)
                    
                    if(optional()): 
                        tmp_Lane['connectsTo'] = []
                        # max 8
                        for t1 in range(random.randint(1,8)):
                            tmp_Connection = {}
                            tmp_Connection['remoteIntersection'] = {'id':random.randint(0,65535)}
                            if(optional()): tmp_Connection['remoteIntersection']['region'] = random.randint(0,65535)
                            if(optional()): 
                                tmp_Connection['connectingLane'] = {}
                                tmp_Connection['connectingLane']['lane'] = random.randint(0,255)
                                if(optional()):
                                    tmp_Connection['connectingLane']['maneuver'] = (random.randint(0,pow(2,12)),12)
                            if(optional()): tmp_Connection['phaseId'] = random.randint(0,255)
                            tmp_Lane['connectsTo'] += [tmp_Connection]
                        
                    
                    if(optional()):
                        tmp_Lane['speedLimits']  =  []
                        # max 9
                        for t2 in range(random.randint(1,9)):
                            tmp_RegulatorySpeedLimit = {}
                            tmp_RegulatorySpeedLimit['type']  = random.choice(['unknown', 'maxSpeedInSchoolZone', 'maxSpeedInSchoolZoneWhenChildrenArePresent',
                                                                            'maxSpeedInConstructionZone','vehicleMinSpeed','vehicleMaxSpeed','vehicleNightMaxSpeed',
                                                                            'truckMinSpeed','truckMaxSpeed','truckNightMaxSpeed','vehiclesWithTrailersMinSpeed',
                                                                            'vehiclesWithTrailersMaxSpeed','vehiclesWithTrailersNightMaxSpeed'])
                            tmp_RegulatorySpeedLimit['speed'] = random.randint(0,8191)
                            
                            tmp_Lane['speedLimits'] += [tmp_RegulatorySpeedLimit]
                    
                    if(optional()):
                        tmp_Lane['points']  =  []
                        # max 31
                        for t3 in range(random.randint(2,4)):
                            tmp_RoadPoint = {}
                            tmp_RoadPoint['posOffset'] = {}
                            tmp_RoadPoint['posOffset']['offsetLL'] = random.choice([ ('position-LL1',{'lon':random.randint(-2048,2047),"lat":random.randint(-2048,2047)}),
                                                                                    ('position-LL2',{'lon':random.randint(-8192,8191),"lat":random.randint(-8192,8191)}),
                                                                                    ('position-LL3',{'lon':random.randint(-32768,32767),"lat":random.randint(-32768,32767)}),
                                                                                    ('position-LL4',{'lon':random.randint(-131072,131071),"lat":random.randint(-131072,131071)}),
                                                                                    ('position-LL5',{'lon':random.randint(-2097152,2097151),"lat":random.randint(-2097152,2097151)}),
                                                                                    ('position-LL6',{'lon':random.randint(-8388608,8388607),"lat":random.randint(-8388608,8388607)}),
                                                                                    ('position-LatLon',{'lon':random.randint(-1799999999,1800000001),"lat":random.randint(-900000000,900000001)}) ])
                            if(optional()):
                                tmp_RoadPoint['posOffset']['offsetV'] = random.choice([ ('offset1',random.randint(-64,63)),
                                                                                        ('offset2',random.randint(-128,127)),
                                                                                        ('offset3',random.randint(-256,255)),
                                                                                        ('offset4',random.randint(-512,511)),
                                                                                        ('offset5',random.randint(-1024,1023)),
                                                                                        ('offset6',random.randint(-2048,2047)),
                                                                                        ('elevation',random.randint(-4096,61439)) ])
                            tmp_Lane['points'] += [tmp_RoadPoint] 

                    
                    tmp_Link['lanes'] += [tmp_Lane]
                
                tmp_Node['inLinks'] += [tmp_Link]
        
        tmp['nodes'] += [tmp_Node]
        
    
    # --- OPTIONAL ---
    # timeStamp MinuteOfTheYear OPTIONAL
    
    if(optional()): tmp['timeStamp'] = random.randint(0,527040)
    
    raw = ('mapFrame',tmp)
    return raw

func_list = [gen_BSM,gen_SPAT,gen_RSM,gen_RSI,gen_MAP]


# 192.168.40.119 i.MX6（use AG15 send to Air）
# 192.168.40.120 OBU/RSU

def save_payload(payload,raw):
    f = open("result.txt",'a+')
    print("[+] success: "+payload.hex())
    print("[+] success: "+str(raw))
    f.write("[+] success+: "+payload.hex() + '\n')
    f.write("[+] success+: "+str(raw) + '\n')
    f.write("-"*40+'\n')
    f.close()

def attack(payload):
    payload_len = len(payload)
    
    if(payload_len<65535):
        head = "04006f"+hex(payload_len)[2:].zfill(4)
        head = bytes.fromhex(head)
        payload  = head + payload
        
        try:
            io = remote("192.168.40.119",8888)
            io.send(p32(len(payload))+payload) 
            io.close()
        except:
            sleep(15)
        
        print("[+] send: "+payload.hex())
        print("[+] send_len: "+str(len(payload)))
    else:
        print("[-] big: "+str(payload_len))
        

def reboot():
    sshio = ssh(host='192.168.40.120',user='root',password='root')
    sshio("reboot")
    sleep(10)

# ------------------ tcp check ------------------ 

tcp_close = False
tcp_init  = False

def init_tcp():
    global tcp_init,tcp_close
    while(1):
        try:
            tcp_init  = False
            io = remote('127.0.0.1',60004)
            tcp_init  = True
            tcp_close = False
            io.wait_for_close()
            tcp_close = True 
            break
        except:
            sleep(1)

def init_check_by_tcp():
    threading.Thread(target=init_tcp).start()
    while(1):
        if(tcp_init):break
        print("waiting")
        print(tcp_init)
        sleep(1)
        
# ------------------ pid check ------------------ 

oldpid = 0

def init_check_by_pid():
    global oldpid
    oldpid = process(["adb","shell", "ps -ef | grep v2x | grep -v 'grep' | awk '{print $2}'"]).recv().split()[0]
    print(oldpid)

def check_by_pid():
    global oldpid
    try:
        newpid = process(["adb","shell", "ps -ef | grep v2x | grep -v 'grep' | awk '{print $2}'"]).recv().split()[0]
        if( oldpid != newpid ):
            oldpid  = newpid
            return 1
        return 0
    except:
        sleep(10)

# ------------------ fuzz loop ------------------ 

def fuzz_loop():
    #init_check_by_pid()
    init_check_by_tcp()
    while 1:
        raw     = func_list[random.randint(0,4)]()
        payload = MsgFrame.MessageFrame.to_uper(raw)
        for j in range(5):
            print("[+] send_raw: "+str(raw))
            attack(payload)
        sleep(0.1)
        #if(check_by_pid()):
        if(tcp_close):
            save_payload(payload,raw)
            # my alert
            os.system("gtimeout 5 alert true &")
            reboot()

fuzz_loop()