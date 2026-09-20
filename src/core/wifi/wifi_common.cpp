#include "core/wifi/wifi_common.h"
#include "core/display.h"
#include "core/mykeyboard.h"
#include "core/powerSave.h"
#include "core/radio_mem.h"
#include "core/ram_profile.h"
#include "core/settings.h"
#include "core/utils.h"
#include "core/wifi/wifi_mac.h"
#include "esp_wifi.h"
#include "modules/ble/ble_common.h"
#include <esp_event.h>
#include <esp_netif.h>
#include <globals.h>

#define WIFI_RECONNECT_POLL_MS 5000
#define WIFI_RECONNECT_MAX_MS 30000

static TaskHandle_t timezoneTaskHandle = NULL;
static bool wifiTransitioning = false;

static portMUX_TYPE wifiReconnectMux = portMUX_INITIALIZER_UNLOCKED;
static volatile bool wifiReconnectArmed = false;
static bool wifiReconnectTaskRunning = false;

esp_err_t wifiRawTx(wifi_interface_t ifx, const void *frame, int len, uint8_t retries) {
    esp_err_t err = esp_wifi_80211_tx(ifx, frame, len, false);
    for (uint8_t i = 0; err == ESP_ERR_NO_MEM && i < retries; i++) {
        vTaskDelay(1); // let the driver drain TX buffers and retry
        err = esp_wifi_80211_tx(ifx, frame, len, false);
    }
    return err;
}

void ensureWifiPlatform() {
    static bool netifInitialized = false;
    static bool eventLoopCreated = false;
    static portMUX_TYPE platformMux = portMUX_INITIALIZER_UNLOCKED;

    portENTER_CRITICAL(&platformMux);
    bool needNetif = !netifInitialized;
    bool needLoop = !eventLoopCreated;
    portEXIT_CRITICAL(&platformMux);

    if (needNetif) {
        ESP_ERROR_CHECK(esp_netif_init());
        portENTER_CRITICAL(&platformMux);
        netifInitialized = true;
        portEXIT_CRITICAL(&platformMux);
    }

    if (needLoop) {
        esp_err_t err = esp_event_loop_create_default();
        if (err != ESP_ERR_INVALID_STATE) { ESP_ERROR_CHECK(err); }
        portENTER_CRITICAL(&platformMux);
        eventLoopCreated = true;
        portEXIT_CRITICAL(&platformMux);
    }
}

// The radio is only ours to reconnect when it sits idle in plain STA mode: attacks,
// sniffers and scans drive it directly and must not be interrupted.
static bool wifiCanReconnect() {
    if (wifiTransitioning) return false;
    if (WiFi.getMode() != WIFI_MODE_STA) return false;
    bool promiscuous = false;
    if (esp_wifi_get_promiscuous(&promiscuous) != ESP_OK || promiscuous) return false;
    if (WiFi.scanComplete() == WIFI_SCAN_RUNNING) return false;
    return true;
}

static void wifiReconnectTask(void *pvParameters) {
    // The link is polled at a fixed pace; only the connect attempts back off
    uint32_t retryMs = WIFI_RECONNECT_POLL_MS;
    uint32_t sinceLastTryMs = 0;
    bool dropped = false;

    for (;;) {
        while (wifiReconnectArmed && bruceConfig.wifiAutoConnect) {
            vTaskDelay(pdMS_TO_TICKS(WIFI_RECONNECT_POLL_MS));
            if (!wifiReconnectArmed || !bruceConfig.wifiAutoConnect) break;

            if (WiFi.isConnected()) {
                if (dropped) {
                    dropped = false;
                    wifiIP = WiFi.localIP().toString(); // DHCP may have handed out a new one
                    log_i("WiFi link restored, IP: %s", wifiIP.c_str());
                }
                retryMs = WIFI_RECONNECT_POLL_MS;
                sinceLastTryMs = 0;
                continue;
            }
            if (!wifiCanReconnect()) continue;

            sinceLastTryMs += WIFI_RECONNECT_POLL_MS;
            if (sinceLastTryMs < retryMs) continue;

            // The driver still holds the config of the last WiFi.begin(). Arduino's own
            // auto-reconnect gives up after one try (e.g. AP still rebooting), so keep retrying.
            dropped = true;
            esp_err_t err = esp_wifi_connect();
            log_i("WiFi link lost, reconnecting (err=%d)", err);
            sinceLastTryMs = 0;
            retryMs = min<uint32_t>(retryMs * 2, WIFI_RECONNECT_MAX_MS);
        }

        portENTER_CRITICAL(&wifiReconnectMux);
        bool rearmed = wifiReconnectArmed && bruceConfig.wifiAutoConnect;
        if (!rearmed) wifiReconnectTaskRunning = false;
        portEXIT_CRITICAL(&wifiReconnectMux);
        if (!rearmed) break;
    }

    vTaskDelete(NULL);
}

static void wifiStaStoppedEvent(arduino_event_id_t event) { wifiReconnectArmed = false; }

void wifiAutoReconnectArm() {
    if (!bruceConfig.wifiAutoConnect) return;
    if (WiFi.getMode() != WIFI_MODE_STA || !WiFi.isConnected()) return;

    static bool eventRegistered = false;

    portENTER_CRITICAL(&wifiReconnectMux);
    wifiReconnectArmed = true;
    bool needTask = !wifiReconnectTaskRunning;
    wifiReconnectTaskRunning = true;
    bool needEvent = !eventRegistered;
    eventRegistered = true;
    portEXIT_CRITICAL(&wifiReconnectMux);

    // Any module that stops the STA interface took the radio over on purpose
    if (needEvent) WiFi.onEvent(wifiStaStoppedEvent, ARDUINO_EVENT_WIFI_STA_STOP);

    if (needTask && xTaskCreate(wifiReconnectTask, "wifiReconnect", 4096, NULL, 1, NULL) != pdPASS) {
        portENTER_CRITICAL(&wifiReconnectMux);
        wifiReconnectTaskRunning = false;
        portEXIT_CRITICAL(&wifiReconnectMux);
    }
}

void wifiAutoReconnectDisarm() { wifiReconnectArmed = false; }

bool _wifiConnect(const String &ssid, int encryption) {
    String password = bruceConfig.getWifiPassword(ssid);
    if (password == "" && encryption > 0) { password = keyboard(password, 63, "Network Password:", true); }
    if (password == "\x1B") return false;
    bool connected = _connectToWifiNetwork(ssid, password);
    bool retry = false;

    while (!connected) {
        wakeUpScreen();

        options = {
            {"Retry",  [&]() { retry = true; } },
            {"Cancel", [&]() { retry = false; }},
        };
        loopOptions(options);

        if (!retry) {
            wifiDisconnect();
            return false;
        }

        password = keyboard(password, 63, "Network Password:", true);
        if (password == "\x1B") {
            wifiDisconnect();
            return false;
        }
        connected = _connectToWifiNetwork(ssid, password);
    }

    if (connected) {
        wifiConnected = true;
        wifiIP = WiFi.localIP().toString();
        bruceConfig.addWifiCredential(ssid, password);
        wifiAutoReconnectArm();

        // Start timezone update in background if not already running
        if (timezoneTaskHandle == NULL) {
            xTaskCreate(updateTimezoneTask, "updateTimezone", 4096, NULL, 1, &timezoneTaskHandle);
        }
    }

    delay(200);
    return connected;
}

bool _connectToWifiNetwork(const String &ssid, const String &pwd) {
    if (FORCE_RADIO_TEARDOWN_ON_SWITCH) {
        if (BLEConnected) {
            displayWarning("Board with no PSRAM, closing BLE Stack");
            vTaskDelay(700 / portTICK_PERIOD_MS);
        }
        stopBLEStack();
        vTaskDelay(300 / portTICK_PERIOD_MS);
    }

    RAM_LOG("wifi pre-mode"); // Wi-Fi is already up from the menu scan by this point
    drawMainBorderWithTitle("WiFi Connect");
    padprintln("");
    padprint("Connecting to: " + ssid + ".");
    WiFi.mode(WIFI_MODE_STA);
    RAM_LOG("wifi post-mode");
    vTaskDelay(10 / portTICK_PERIOD_MS);
    WiFi.begin(ssid, pwd);

    int i = 1;
    while (!WiFi.isConnected()) {
        if (tft.getCursorX() >= tftWidth - 12) {
            padprintln("");
            padprint("");
        }
#ifdef HAS_SCREEN
        tft.print(".");
#else
        Serial.print(".");
#endif

        if (i > 20) {
            displayError("Wifi Offline");
            vTaskDelay(500 / portTICK_RATE_MS);
            break;
        }

        vTaskDelay(500 / portTICK_RATE_MS);
        i++;
    }

    return WiFi.isConnected();
}

bool _setupAP() {
    IPAddress AP_GATEWAY(172, 0, 0, 1);
    WiFi.softAPConfig(AP_GATEWAY, AP_GATEWAY, IPAddress(255, 255, 255, 0));
    WiFi.softAP(bruceConfig.wifiAp.ssid, bruceConfig.wifiAp.pwd, 6, 0, 4, false);
    wifiIP = WiFi.softAPIP().toString(); // update global var
    Serial.println("IP: " + wifiIP);
    wifiConnected = true;
    return true;
}

void wifiDisconnect() {
    wifiTransitioning = true;
    wifiAutoReconnectDisarm();

    wifi_mode_t mode = WiFi.getMode();
    if (mode & WIFI_MODE_AP) {
        WiFi.softAPdisconnect();
        vTaskDelay(10 / portTICK_PERIOD_MS);
    }
    if (mode & WIFI_MODE_STA) {
        WiFi.disconnect(false, true);
        vTaskDelay(10 / portTICK_PERIOD_MS);
    }
    if (mode != WIFI_MODE_NULL) {
        WiFi.mode(WIFI_OFF);
        vTaskDelay(10 / portTICK_PERIOD_MS);
    }

    wifiConnected = false;
    wifiTransitioning = false;
}

bool wifiConnectMenu(wifi_mode_t mode) {
    if (WiFi.isConnected()) return false; // safeguard

    if (FORCE_RADIO_TEARDOWN_ON_SWITCH) {
        stopBLEStack();
        vTaskDelay(100 / portTICK_PERIOD_MS);
    }

    // Check if WiFi is in transition
    if (wifiTransitioning) {
        displayTextLine("WiFi busy, please wait...");
        vTaskDelay(500 / portTICK_PERIOD_MS);
        return false;
    }

    switch (mode) {
        case WIFI_AP: // access point
            WiFi.mode(WIFI_AP);
            return _setupAP();
            break;

        case WIFI_STA: { // station mode
            int nets;
            if (!radioHasMemForWifi()) {
                displayError("Low RAM: free BLE/SD first", true);
                return false;
            }
            WiFi.mode(WIFI_MODE_STA);

            // wifiMACMenu();
            applyConfiguredMAC();

            bool refresh_scan = false;
            do {
                displayTextLine("Scanning..");
                nets = WiFi.scanNetworks();

                String selSsid = "";
                int selEnc = 0;
                bool selHidden = false;

                options = {};
                for (int i = 0; i < nets; i++) {
                    if (options.size() < 250) {
                        String ssid = WiFi.SSID(i);
                        int encryptionType = WiFi.encryptionType(i);
                        int32_t rssi = WiFi.RSSI(i);
                        int32_t ch = WiFi.channel(i);
                        // Check if the network is secured
                        String encryptionPrefix = (encryptionType == WIFI_AUTH_OPEN) ? "" : "#";
                        String encryptionTypeStr;
                        switch (encryptionType) {
                            case WIFI_AUTH_OPEN: encryptionTypeStr = "Open"; break;
                            case WIFI_AUTH_WEP: encryptionTypeStr = "WEP"; break;
                            case WIFI_AUTH_WPA_PSK: encryptionTypeStr = "WPA/PSK"; break;
                            case WIFI_AUTH_WPA2_PSK: encryptionTypeStr = "WPA2/PSK"; break;
                            case WIFI_AUTH_WPA_WPA2_PSK: encryptionTypeStr = "WPA/WPA2/PSK"; break;
                            case WIFI_AUTH_WPA2_ENTERPRISE: encryptionTypeStr = "WPA2/Enterprise"; break;
                            case WIFI_AUTH_WPA3_PSK: encryptionTypeStr = "WPA3/PSK"; break;
                            case WIFI_AUTH_WPA2_WPA3_PSK: encryptionTypeStr = "WPA2/WPA3/PSK"; break;
                            default: encryptionTypeStr = "Unknown"; break;
                        }

                        String optionText = encryptionPrefix + ssid + "(" + String(rssi) + "|" +
                                            encryptionTypeStr + "|ch." + String(ch) + ")";

                        options.push_back({optionText.c_str(), [&selSsid, &selEnc, ssid, encryptionType]() {
                                               selSsid = ssid;
                                               selEnc = encryptionType;
                                           }});
                    }
                }
                WiFi.scanDelete();
                options.push_back({"Hidden SSID", [&selHidden]() { selHidden = true; }});
                addOptionToMainMenu();

                loopOptions(options);
                options.clear();

                if (returnToMenu) {
                    refresh_scan = false;
                } else if (selHidden) {
                    String __ssid = keyboard("", 32, "Your SSID");
                    if (__ssid != "\x1B") _wifiConnect(__ssid.c_str(), 8);
                    refresh_scan = false;
                } else if (selSsid != "") {
                    _wifiConnect(selSsid, selEnc);
                    refresh_scan = false;
                } else if (check(EscPress)) {
                    refresh_scan = true;
                } else {
                    refresh_scan = false;
                }
            } while (refresh_scan);
        } break;

        case WIFI_AP_STA: // repeater mode
                          // _setupRepeater();
            break;

        default: // error handling
            Serial.println("Unknown wifi mode: " + String(mode));
            break;
    }

    if (returnToMenu) {
        wifiDisconnect(); // Forced turning off the wifi module if exiting back to the menu
        return false;
    }
    return wifiConnected;
}

bool wifiConnectKnownNetSilent() {
    if (WiFi.isConnected()) return true;

    if (FORCE_RADIO_TEARDOWN_ON_SWITCH) {
        stopBLEStack();
        vTaskDelay(100 / portTICK_PERIOD_MS);
    }

    // Check if WiFi is in transition
    if (wifiTransitioning) return false;

    // No-PSRAM guard: don't bring Wi-Fi up if the contiguous DMA block is too
    // small (e.g. BLE already active) — the scan would half-init the driver and
    // crash on teardown. Silent bail: this runs from background tasks.
    if (!radioHasMemForWifi()) return false;

    WiFi.mode(WIFI_MODE_STA);
    int nets = WiFi.scanNetworks();
    String ssid;
    String pwd;

    for (int i = 0; i < nets && !WiFi.isConnected(); i++) {
        ssid = WiFi.SSID(i);
        pwd = bruceConfig.getWifiPassword(ssid);
        if (pwd == "") continue;

        WiFi.begin(ssid, pwd);
        for (int i = 0; i < 50; i++) {
            if (WiFi.isConnected()) {
                wifiConnected = true;
                wifiIP = WiFi.localIP().toString();
                wifiAutoReconnectArm();

                // Start timezone update in background if not already running
                if (timezoneTaskHandle == NULL) {
                    xTaskCreate(updateTimezoneTask, "updateTimezone", 4096, NULL, 1, &timezoneTaskHandle);
                }
                drawStatusBar();
                break;
            }
            vTaskDelay(100 / portTICK_RATE_MS);
        }
    }
    WiFi.scanDelete();

    return WiFi.isConnected();
}

void wifiConnectTask(void *pvParameters) {
    wifiConnectKnownNetSilent();
    vTaskDelete(NULL);
}

String checkMAC() { return String(WiFi.macAddress()); }

bool wifiConnecttoKnownNet(void) {
    if (WiFi.isConnected()) return true; // safeguard

    if (FORCE_RADIO_TEARDOWN_ON_SWITCH) {
        stopBLEStack();
        vTaskDelay(100 / portTICK_PERIOD_MS);
    }

    // Check if WiFi is in transition
    if (wifiTransitioning) {
        displayTextLine("WiFi busy, please wait...");
        vTaskDelay(500 / portTICK_PERIOD_MS);
        return false;
    }

    // No-PSRAM guard: refuse before the scan brings Wi-Fi up in low memory.
    if (!radioHasMemForWifi()) {
        displayError("Low RAM: free BLE/SD first", true);
        return false;
    }

    bool result = false;
    int nets;
    // WiFi.mode(WIFI_MODE_STA);
    displayTextLine("Scanning Networks..");
    WiFi.disconnect(true, true);
    vTaskDelay(10 / portTICK_PERIOD_MS);
    nets = WiFi.scanNetworks();
    for (int i = 0; i < nets; i++) {
        vTaskDelay(10 / portTICK_PERIOD_MS);
        String ssid = WiFi.SSID(i);
        String password = bruceConfig.getWifiPassword(ssid);
        if (password != "") {
            Serial.println("Connecting to: " + ssid);
            result = _connectToWifiNetwork(ssid, password);
        }
        // Maybe it finds a known network and can't connect, then try the next
        // until it gets connected (or not)
        if (result) {
            Serial.println("Connected to: " + ssid);
            break;
        }
    }
    if (WiFi.isConnected()) {
        wifiConnected = true;
        wifiIP = WiFi.localIP().toString();
        wifiAutoReconnectArm();

        // Start timezone update in background if not already running
        if (timezoneTaskHandle == NULL) {
            xTaskCreate(updateTimezoneTask, "updateTimezone", 4096, NULL, 1, &timezoneTaskHandle);
        }
    }
    return result;
}

void updateTimezoneTask(void *pvParameters) {
    // Wait a bit for connection to stabilize before updating timezone
    vTaskDelay(5000 / portTICK_PERIOD_MS);

    // Only update timezone if WiFi is still connected
    if (WiFi.isConnected() && wifiConnected) { updateClockTimezone(); }

    // Clear the task handle before deleting
    timezoneTaskHandle = NULL;
    vTaskDelete(NULL);
}
