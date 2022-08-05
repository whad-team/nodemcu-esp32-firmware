NodeMCU ESP32 WHAD compatible firmware
======================================

This firmware supports the following features:

- BLE scanning (active and passive scan)
- Central role (able to initiate a connection to a BLE device)
- Peripheral role (able to accept a connection from a BLE device)

This firmware relies on a hack of Espressif BLE ROM and some control PDUs cannot
be manipulated as it is required by the underlying BLE controller to properly
manage any BLE connection. However, PDU can be fully manipulated and this firmware
can be used to develop a BLE fuzzer.

Building the firmware
---------------------

Use the latest version of ESP-IDF, installation and usage described in their
`getting started documentation <https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/index.html>`_.