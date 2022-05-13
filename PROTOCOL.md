=================================
ESP32-NodeMCU / Computer protocol
=================================

Establishing communication with our ESP32
=========================================

UART
----

Communication with ESP32 is done through USB, thanks to the ESP32 NodeMCU
UART adapter (included on the board). Interface UART0 is configured as follows:
- baudrate: 115200
- parity: None
- data size: 8 bit
- flow control: None


Sync word
---------

Since ESP32 will send some early messages on UART0, we need some kind of sync
word to know when our firmware has taken ownership of UART0. 

The chosen sync word is: "ESP_BLE_FUZZ".


Communication protocol
======================

Message format
--------------

4-byte header with variable-size content:

```
+0x00: Message Marker (0xEB)
+0x01: Message type
+0x02: Message length (uint8)
+0x03: Header checksum
+0x04: Message content
```

Message types
-------------

Messages to drive NimBLE stack:

- 0x01: SCAN, launches/stops a BLE scan through NimBLE
- 0x02: ADVERT, reports advertising data received during scan (NimBLE)
- 0x03: SCANRSP, reports scan response data received during scan (NimBLE)
- 0x04: CONNECT, connect to a target device
- 0x06: DISCOVER, discovers services and characteristics (NimBLE)
- 0x07: READ_HND, read from a characteristic/descriptor handle
- 0x08: WRITE_HND, write to a characteristic/descriptor handle
- 0x09: WRITE_CMD, write command to a characteristic
- 0x0A: DISCONNECT, disconnect from a device (if connected)

Event messages:
- 0x40: CONNECTED, notify host that target device is connected
- 0x41: SERVICE, discovered service information
- 0x42: CHARAC, discovered characteristic information
- 0x43: DISCOVERED, notify services and characteristics discovered done
- 0x44: NOTIFICATION_DATA, notification received for characteristic
- 0x45: CHAR_DATA, data received from characteristic read


Messages to access raw control/pdu data
- 0x80: EN_RAW, enable/disable raw mode
- 0x81: RX_DATA, data received by client
- 0x82: TX_DATA, send raw data
- 0x83: RX_CTL, control PDU received by client
- 0x84: TX_CTL, send control PDU

Status messages:
- 0x00: VERSION, provides software major/minor/revision versions as well as hardware type (ESP32, ESP32-S2, etc.)
- 0xFF: ERROR, error/success occured (including disconnection)


VERSION
-------

This message provides firmware major/minor/rev versions as well as hardware type.

```
+0x00: Device type
+0x01: Major
+0x02: Minor
+0x03: Revision
```

Known devices:

- 0x01: ESP32

ERROR
-----

This message provides information about error/success that may occur. It holds
a single byte describing the error/success code.

```
+0x00: Error code
```

Known error codes:

- 0x00: Success (MS style !)
- 0x02: Wrong/unknown command
- 0x03: Bad command checksum
- 0x04: Connection lost / device disconnected


SCAN
----

This message enables or disables an active BLE scan (managed by NimBLE).

```
+0x00: Enable (bool)
+0x01: Parameters
```

Set `Enable` to 1 to enable, 0 to disable.

`Parameters` hold a set of options:

- 0x01: filter duplicates
- 0x02: active scan (scan request are sent in active mode)


ADVERT
------

This message is sent by the firmware each time an advertising event is seen.

```
+0x00: IND_ADV data
```


SCANRSP
-------

This message is sent by the firmware each time a scan response is seen (only
if active scan is enabled).

```
+0x00: SCAN_RSP data
```

CONNECT
-------

This message is sent to the firmware to initiate a connection to a target
device.

```
+0x00: Target BD address (6 bytes)
```

CONNECTED
---------

This message is sent by the firmware once a connection to the target device
has successfully been initiated.

```
+0x00: Device BD address (6 bytes)
```

DISCOVER
--------

This message is sent to the firmware to enable services and characteristics
discovery.

This message has no parameters (yet).


DISCOVERED
----------

This message is sent by the firmware to notify the success of the services and
characteristics discovery.

```
+0x00: Number of discovered services (uint8)
+0x01: Number of discovered characteristics (uint8)
```

SERVICE
-------

This message is sent by the firmware to report to the host a discovered service.

```
+0x00: Service handle (uint16)
+0x02: Service Attribute permission
+0x02: Service UUID (variable size)
```

CHARAC
------

This message is sent by the firmware to report to the host a discovered characteristic.

```
+0x00: Service handle (uint16)
+0x02: Characteristic handle
+0x04: Characteristic value handle (uint16)
+0x06: Characteristic desc handle (uint16)
+0x08: Characteristic properties
+0x09: Characteristic UUID (variable size)
```


READ_HND
--------

This message is sent to the firmware to request a characteristic read.

```
+0x00: Characteristic handle
```

CHAR_DATA
---------

This message is sent by the firmware when a characteristic has been successfully
read.

```
+0x00: Characteristic handle (uint16)
+0x02: Characteristic data
```

WRITE_HND
---------

This message is sent to the firmware to request a characteristic/descriptor write.

``` 
+0x00: Characteristic handle (uint16)
+0x02: Data to write to this characteristic
```

WRITE_CMD
---------

This message is sent to the firmware to request a characteristic/descriptor write command.

``` 
+0x00: Characteristic handle (uint16)
+0x02: Data to write to this characteristic
```


DISCONNECT
----------

This message is sent to disconnect the remote device.

```
+0x00: Reason
```


EN_RAW
------

This message is sent to the firmware to enable/disable raw mode access.
Raw mode is disabled by default, and reset each time a CONNECT message is
received by the firmware.

```
+0x00: Enable (bool)
``` 

Set `Enable` to 1 to enable raw mode, 0 to disable.


RX_DATA
-------

This message is sent by the firmware each time a data PDU is received.

```
+0x00: data PDU
```

TX_DATA
-------

This message is sent to the firmware to send a raw data PDU.

```
+0x00: data PDU to be sent
```

RX_CTL
------

This message is sent by the firmware each time a control PDU is received.

```
+0x00: control PDU
```

TX_CTL
------

This message is sent to the firmware to send a raw control PDU.

```
+0x00: control PDU to be sent
```

NOTIFICATION_DATA
-----------------

This message is sent by the firmware to notify a notification (data written to a characteristic).

```
+0x00: Characteristic handle (uint16)
```

