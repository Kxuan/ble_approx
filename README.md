# BLE Approx
Automatically execute scripts by BLE device proximity

## Dependency
bluez >= 5

## Build Step
```
$ mkdir build
$ cmake ..
$ make
$ sudo make install
```

## Usage
```
Usage: ble_approx [options] <Address>
        [--verbose]    Print verbose logs (RSSI, exec log, etc.)
        [--onapproach] Program to execute when device approaching
        [--onleave]    Program to execute when device left
        [--seconds]    The number of seconds the device is determined to have left. (Default 20s)
        [--rssi]       Ignore BLE packets which RSSI is less than this value. (Default -80)
```

## Example
Automatically lock/unlock your screen by BLE device proximity
```
sudo ble_detect --onapproach ./cinnamon-unlock --onleave ./cinnamon-lock --seconds 60 c1:87:bf:ff:ff:ff
```

## Note
The program does not use any authentication mechanism. It detect the device using the MAC address of your BLE device only.  
However, the MAC address of your BLE device can be cloned by **ANY OTHER** device.

# Author
kXuan <kxuanobj@gmail.com>

# License
MIT