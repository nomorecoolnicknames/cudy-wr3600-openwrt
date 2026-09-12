// Cudy WR3600: replaces wifi-scripts' detection. The two radios are known
// (wl0 = phy0 = 5 GHz, wl1 = phy1 = 2.4 GHz) and /etc/config/wireless ships
// with the firmware; the stock detector would skip them anyway (the blob's
// wiphys have no device path) or add duplicates. Print nothing.
