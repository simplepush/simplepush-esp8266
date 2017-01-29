#include <Arduino.h>

#include <ESP8266WiFi.h>
#include <ESP8266WiFiMulti.h>

#include <Simplepush.h>

#define USE_SERIAL Serial

ESP8266WiFiMulti WiFiMulti;
Simplepush simple;

void setup() {
	USE_SERIAL.begin(115200);
	USE_SERIAL.setDebugOutput(true);

	USE_SERIAL.println();
	USE_SERIAL.println();
	USE_SERIAL.println();

	for(uint8_t t = 4; t > 0; t--) {
		USE_SERIAL.printf("[SETUP] WAIT %d...\n", t);
		USE_SERIAL.flush();
		delay(1000);
	}

	WiFiMulti.addAP("YourWifiSSID", "WifiPassword");
}

void loop() {
	if((WiFiMulti.run() == WL_CONNECTED)) {
		simple.send("YourSimplepushKey", "Wow", "This is so easy", "Event");
		simple.send("YourSimplepushKey", NULL, "No title and no event. Just a message.", NULL);
		simple.sendEncrypted("YourSimplepushKey", "password", "salt", "Wow", "This is so secure.", "Event");
		delay(5000);
	}
}
