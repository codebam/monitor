import util from 'util';
import { exec } from 'child_process';
import fs from 'fs/promises';
import { parseStringPromise } from 'xml2js';

// Promisify exec for async/await
const execPromise = util.promisify(exec);

// --- Configuration ---
const SCAN_TARGET = '10.15.71.1/24';
const XML_FILE = '/tmp/nmap_scan.xml';
const SCAN_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes
// ---------------------

// This holds the results from the last scan
let previousHosts = new Set();

/**
 * Runs nmap, reads the XML output, and returns a Set of active hosts.
 */
async function getActiveHosts() {
  try {
    // 1. Run the nmap scan
    console.log(`Scanning ${SCAN_TARGET}...`);
    await execPromise(`run0 nix run nixpkgs#nmap -- -sn -n -oX ${XML_FILE} ${SCAN_TARGET}`);

    // 2. Read the XML file
    const xmlData = await fs.readFile(XML_FILE, 'utf8');

    // 3. Parse the XML data
    const result = await parseStringPromise(xmlData);

    // 4. Extract active hosts
    const activeHosts = new Set();
    
    // Check if result.nmaprun.host exists
    if (result.nmaprun && result.nmaprun.host) {
      
      // Ensure 'hosts' is always an array
      const hosts = Array.isArray(result.nmaprun.host) ? result.nmaprun.host : [result.nmaprun.host];
      
      hosts
        .filter(host => host && host.status && host.status[0] && host.status[0].$ && host.status[0].$.state === 'up')
        .forEach(host => {
          
          // Ensure 'host.address' is always an array
          const addresses = Array.isArray(host.address) ? host.address : [host.address];
          
          // --- START OF FIX ---
          // Find the IP address object (looking for 'ipv4' instead of 'ip')
          const ipObj = addresses.find(addr => addr && addr.$ && addr.$.addrtype === 'ipv4');
          // --- END OF FIX ---
          
          // If no IP, we can't identify it, so skip.
          if (!ipObj) {
            return; // Skips this host
          }
          
          const ip = ipObj.$.addr;

          // Find the MAC address object (this is optional)
          const macObj = addresses.find(addr => addr && addr.$ && addr.$.addrtype === 'mac');
          
          // Build the unique identifier, safely checking if macObj exists
          const hostIdentifier = macObj 
            ? `${ip} (${macObj.$.addr} - ${macObj.$.vendor || 'Unknown'})` 
            : `${ip} (No MAC)`;
            
          activeHosts.add(hostIdentifier);
        });
    }
    return activeHosts;

  } catch (err) {
    console.error(`[Error] Scan failed: ${err.stack}`);
    // Return an empty set so the main loop can continue
    return new Set();
  }
}

/**
 * Compares the new scan results with the previous results and logs/notifies changes.
 */
async function checkForChanges() {
  const currentHosts = await getActiveHosts();

  // Don't notify on the very first scan to avoid a huge list
  const isFirstScan = previousHosts.size === 0;

  const newDevices = [];
  const leftDevices = [];

  // Check for new devices
  for (const host of currentHosts) {
    if (!previousHosts.has(host)) {
      newDevices.push(host);
    }
  }

  // Check for devices that left
  for (const host of previousHosts) {
    if (!currentHosts.has(host)) {
      leftDevices.push(host);
    }
  }

  const hasChanges = newDevices.length > 0 || leftDevices.length > 0;

  // 1. Log to console
  if (hasChanges) {
    newDevices.forEach(host => console.log(`[+] NEW DEVICE: ${host}`));
    leftDevices.forEach(host => console.log(`[-] DEVICE LEFT: ${host}`));
  } else {
    console.log(`No changes. ${currentHosts.size} hosts active.`);
  }

  // 2. Send desktop notification
  // We skip the first scan to avoid a flood of "new device" notifications
  if (hasChanges && !isFirstScan) {
    try {
      if (newDevices.length > 0) {
        const title = 'Network: New Devices';
        // The body can contain newlines, which notify-send supports
        const body = `Found ${newDevices.length} new device(s):\n${newDevices.join('\n')}`;
        
        // -t 5000 makes the notification auto-close after 5 seconds
        await execPromise(`notify-send -t 5000 "${title}" "${body}"`);
      }
      
      if (leftDevices.length > 0) {
        const title = 'Network: Devices Left';
        const body = `${leftDevices.length} device(s) left:\n${leftDevices.join('\n')}`;
        
        await execPromise(`notify-send -t 5000 "${title}" "${body}"`);
      }
    } catch (err) {
      console.error(`[Error] Failed to send notification: ${err.message}`);
    }
  }

  // 3. Update the state for the next run
  previousHosts = currentHosts;
}

/**
 * Main function to start the monitor
 */
async function main() {
  console.log('Starting network monitor. Running initial scan...');
  await checkForChanges(); // Run once immediately
  
  // Set interval to run every 5 minutes
  setInterval(checkForChanges, SCAN_INTERVAL_MS);
  console.log(`Scan complete. Next scan in 5 minutes.`);
}

main();
