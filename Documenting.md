### 1. **VirtualBox Network Configuration: Forging My Private Lab Network**

My primary objective here is to create a totally isolated network inside VirtualBox. This is a non-negotiable step because if my Metasploitable2 VM gets exploited (which, let's be honest, is the whole point!), I need absolute certainty that those vulnerabilities stay strictly within my lab environment and don't spill over onto my actual home network. For this, I'm utilizing VirtualBox's **Host-Only Network** feature.

#### 1.1. **Crafting My Dedicated VirtualBox Host-Only Network**

* **My Action:** This was my very first move, the foundational building block for this entire network lab. On my Windows host PC, I opened the main VirtualBox Manager application. I knew I needed a dedicated, private network just for my lab VMs to talk to each other, so I navigated to the top menu: `File > Host Network Manager...`. In this window, I clicked to create a new Host-Only Network. VirtualBox usually assigns a default name like `VirtualBox Host-Only Ethernet Adapter` and an IP address range (mine typically defaults to `192.168.56.0/24`, which is perfect for my needs). I made absolutely sure that its **DHCP Server was enabled**. This is a crucial detail because it means VirtualBox will automatically assign IP addresses to my Kali and Metasploitable2 VMs when they connect to this network, saving me the headache of manually configuring IPs later on. Getting this initial network bridge set up correctly feels like laying down a super solid, secure foundation!

    ![VirtualBox Host Network Manager]<img width="960" alt="image" src="https://github.com/user-attachments/assets/df7064d8-f44d-4882-a4b7-84de45dc4840" />


#### 1.2. **Configuring My Kali Linux VM for Dual Network Power**

* **My Action:** Now that my private lab network was forged, it was time to hook up my Kali Linux VM. This was a critical step, as Kali needs to do two things: talk to the internet for updates and downloads, AND talk to my vulnerable Metasploitable2 VM on our new private network. So, I carefully powered off my Kali VM first – you can't mess with network adapters while it's running! Once it was off, I right-clicked on Kali in the VirtualBox Manager, went to `Settings`, and then hit `Network`.

    * **Adapter 1 (NAT):** This one was already set up as `NAT`, and I left it exactly as is. This adapter is my Kali VM's lifeline to the outside world – perfect for downloading tools, getting updates, and accessing online resources without interfering with my lab.

    * **Adapter 2 (Host-Only Network for the Lab!):** This was the exciting part. I checked "Enable Network Adapter" for Adapter 2. For "Attached to:", I chose **`Host-only Adapter`** and then, from the "Name" dropdown, I *carefully selected the exact Host-Only Network I just created* (`VirtualBox Host-Only Ethernet Adapter`). This ensures Kali is now physically connected to our isolated lab segment.

    * **Promiscuous Mode (The Super Important Bit!):** This setting is non-negotiable for a monitoring station. I expanded the "Advanced" section and set `Promiscuous Mode` to **`Allow All`**. Why "Allow All"? Because my IDS tools (like Suricata and Zeek) need to "see" *every single packet* flowing across that Host-Only Network – not just packets addressed directly to Kali. This is how they can detect attacks targeting Metasploitable2, even if Kali isn't the direct recipient. It's like giving Kali super-hearing for network traffic! Once everything was configured, I clicked `OK` to save the settings.

    ![Kali Linux VM Network Settings]<img width="960" alt="image" src="https://github.com/user-attachments/assets/b660fa0d-70fb-4c17-8eaa-daeb568e9d49" />


 ### 2. **Setting Up My Vulnerable Target: Metasploitable2 - The Practice Dummy!**

Now that my Kali monitoring station is ready to go, it's time to bring in the "practice dummy" – my Metasploitable2 VM. This machine is deliberately designed to be riddled with vulnerabilities, making it the perfect, safe environment for me to simulate attacks against and generate the kind of network traffic my IDS tools will feast on. This is where the real fun of ethical hacking and detection comes into play!

#### 2.1. **Hunting Down and Downloading Metasploitable2**

* **My Action:** My first mission was to acquire the Metasploitable2 VM. I knew it was readily available from SourceForge, so I headed straight to their official project page. It typically comes as a compressed `.zip` file containing a `.vmdk` (Virtual Machine Disk) file, which is essentially the virtual hard drive for the VM. After downloading the `.zip`, I carefully extracted the `.vmdk` file to a place on my host PC where I could easily find it for importing into VirtualBox. This little file is going to be central to all my network security experiments!
* **Source:** `https://sourceforge.net/projects/metasploitable/files/Metasploitable2/`


    ![Metasploitable2  VMDK]![image](https://github.com/user-attachments/assets/75569095-ddc2-4b11-861e-468e7d8a163a)

#### 2.2. **Bringing Metasploitable2 into My Virtual Lab (Import Process)**

* **My Action:** Once the `metasploitable-linux-2.0.0.vmdk` file was finally on my host system, I needed to get it into VirtualBox. Since the "Import Appliance" option usually expects an `.ova` or `.ovf` file, I used the "Create New Virtual Machine" wizard. I opened my VirtualBox Manager and clicked `Machine > New`. I gave the new VM a clear name like "Metasploitable2", set its operating system type to Linux, and crucially, on the hard disk step, I selected **"Use an existing virtual hard disk file"** and browsed to where I saved the `Metasploitable.vmdk` file. I allocated 1 CPU core and 512 MB of RAM, which is more than enough for this lightweight, vulnerable machine. The process successfully linked the raw virtual disk to my new VM, getting it ready for deployment!


    ![Importing Metasploitable2 Appliance]![image](https://github.com/user-attachments/assets/57ee134c-67b9-4bf4-ad16-f69e10cf2ab2)

#### 2.3. **Connecting Metasploitable2 to Our Isolated Lab Network**

* **My Action:** With Metasploitable2 successfully imported and its virtual disk attached, the absolute next crucial step was to connect it *only* to our isolated Host-Only Network. This is paramount for security – I absolutely do *not* want this vulnerable machine touching my home network or the internet directly. So, I powered off the Metasploitable2 VM (it might automatically start after import, so make sure it's off). Then, in VirtualBox Manager, I right-clicked on "Metasploitable2" > `Settings` > `Network`.

    * **Adapter 1 (Host-Only Network ONLY!):** I checked "Enable Network Adapter" for Adapter 1. For "Attached to:", I selected **`Host-only Adapter`**. Then, under "Name:", I carefully picked the *same Host-Only Network* that my Kali VM is connected to (`VirtualBox Host-Only Ethernet Adapter`). This ensures both VMs are on the same isolated virtual network.
    * **No Internet for the Target:** I made absolutely sure that no other network adapters (like NAT) were enabled for Metasploitable2. This strict isolation is a core security principle for a vulnerable lab machine. Its `Promiscuous Mode` could be left at `Deny` or `Allow VMs` because it's the target, not the monitor. Finally, I clicked `OK` to save its network configuration. Now, my vulnerable target is safely contained and ready to be attacked and monitored within our lab!


    ![Metasploitable2 VM Network Settings]![image](https://github.com/user-attachments/assets/a7eaaccb-e06b-4790-ad95-848e5c5691c5)

### 3. **Verifying Network Connectivity: Pinging Our Way to Success!**

With both my Kali Linux VM and Metasploitable2 VM meticulously configured on the same Host-Only Network, the next crucial step is to power them on and confirm they can actually communicate. This "ping test" is simple but absolutely vital; it confirms our isolated lab network is functional and ready for monitoring.

#### 3.1. **Powering On and Identifying IP Addresses**

* **My Action:** First things first, I powered on both my **Kali Linux VM** and my **Metasploitable2 VM** in VirtualBox. Once they both booted up, I logged into each of them. My immediate task was to find out what IP addresses they were assigned on our new Host-Only Network by the VirtualBox DHCP server.

    * **On Kali Linux:** I opened a terminal and used the `ip a` command. I looked for the interface that corresponded to my Host-Only Adapter (it's usually `eth1` or something like `enp0s8` if `eth0` is your NAT adapter). I noted down its IP address (it should be in the `192.168.56.x` range).
    * **On Metasploitable2:** After logging in with the default credentials (username: `msfadmin`, password: `msfadmin`), I opened a terminal and used the `ifconfig` command. I looked for its primary Ethernet interface's IP address, which also should be in the same `192.168.56.x` range as Kali's Host-Only IP.

    Knowing both IPs is like getting the street addresses for my lab machines!

    ![Identifying VM IP Addresses]![VirtualBox_Kali Linux_29_06_2025_02_00_09](https://github.com/user-attachments/assets/bc2b4c16-774f-4e4a-bc34-2e0bf7e0d8f3)  ![VirtualBox_Metasploitable2_29_06_2025_01_57_31](https://github.com/user-attachments/assets/8e67548e-ded6-476a-bfdf-24fa72566b80)

#### 3.2. **Performing the Ping Test: The Communication Check**

* **My Action:** With both IP addresses confirmed (`192.168.117.2` for Kali's Host-Only adapter and `192.168.117.3` for Metasploitable2), it was time for the ultimate test: a ping! This simple command sends network packets to the other machine and listens for a reply, confirming that they can "see" each other across our isolated Host-Only network. This time, after re-confirming that Kali's Adapter 2 (the Host-Only interface) was correctly enabled and had `Promiscuous Mode: Allow All`, I was confident.

    * **From Kali Linux to Metasploitable2:** I opened a terminal on my Kali VM and executed a ping command, targeting Metasploitable2's IP address.
        ```bash
        ping 192.168.117.3
        ```
    * **The result was an absolute success!** I saw multiple replies, confirming 0% packet loss. This was a hugely satisfying moment after all the network configuration and troubleshooting!

* **Screenshot:**
    **Show a terminal window on your Kali Linux VM displaying a successful ping to your Metasploitable2 VM's IP address (e.g., `ping 192.168.117.3`) with clear "time=" replies and no packet loss.**
    ![Successful Ping from Kali to Metasploitable2]!![VirtualBox_Kali Linux_29_06_2025_02_38_44](https://github.com/user-attachments/assets/c78c1d5c-a723-45b1-a425-83e412cbb1ff)


## 🛡️ **Phase 2: Deploying Our Network Sentinel - Suricata IDS**

With my isolated lab network finally humming, it's time to bring in the big guns: **Suricata**. This open-source Intrusion Detection System (IDS) is going to be my eyes and ears on the network. It's designed to inspect network traffic for malicious patterns, known attack signatures, and suspicious anomalies, alerting me when it finds something interesting. Placing it on my Kali VM, which is already configured for `Promiscuous Mode` on the Host-Only network, makes it perfectly positioned to monitor everything happening between Kali and Metasploitable2. This is where I start turning raw network data into actionable security intelligence!

### 1. **Installing Suricata on Kali Linux**

* **My Action:** As with any good tool in Kali, the first step is installation. I ensured my Kali VM had internet access (via its NAT adapter) and then opened a terminal. A quick `apt update` ensures I'm getting the latest package information, followed by the installation command for Suricata.

    ```bash
    sudo apt update
    sudo apt install suricata -y
    ```
    I waited for the installation to complete. This installs the core Suricata engine and its default configuration files, bringing my network sentinel online.
    ![Installing Suricata on Kali Linux]![VirtualBox_Kali Linux_29_06_2025_02_59_25](https://github.com/user-attachments/assets/00802c07-544f-483c-81cf-121f60bd413c)

### 1.2. **Re-enabling Kali's Host-Only Network for Lab Monitoring**

* **My Action:** To install Suricata, I had temporarily disabled Kali's Host-Only network adapter (Adapter 2) to resolve an internet connectivity issue with its NAT adapter. Now that Suricata is installed, it's absolutely crucial to re-enable Adapter 2 so Kali can once again connect to and monitor the Metasploitable2 VM on our isolated lab network. Without this, Suricata wouldn't "see" any traffic between my attacker and target machines. I powered off Kali, re-enabled the adapter in VirtualBox settings (ensuring `Promiscuous Mode: Allow All` was set), and powered it back on.
    ![Kali Linux Network Adapters - Both Enabled]<img width="579" alt="image" src="https://github.com/user-attachments/assets/ca8618f6-e3f9-43b2-aa0c-73e6ee7cedf1" />
    ### 1.3. **Verifying Kali's Dual Network Connectivity (Internet & Lab)**

* **My Action:** After re-enabling Kali's Host-Only Adapter (Adapter 2) and booting the VM, it was essential to confirm that both network interfaces were active and functioning as expected. This meant verifying both internet access (via NAT) and connectivity to my isolated lab network (via Host-Only). This step ensures Kali is ready to both fetch updates and rules for Suricata *and* monitor traffic within my lab. I noted a persistent quirk where enabling Adapter 2 for Host-Only connectivity caused Adapter 1 (NAT) to lose its internet connection, resulting in a "Network is unreachable" error for external pings. However, connectivity to the Metasploitable2 VM on the isolated lab network remained fully functional.

    * **Verify Internet Access (NAT - eth0):** I opened a terminal and attempted to ping a public IP address like Google's DNS server (`8.8.8.8`). This failed, confirming the temporary internet connectivity issue when both adapters are active.
        ```bash
        ping 8.8.8.8
        ```
        (Output shows "Network is unreachable")

    * **Verify Lab Network Access (Host-Only - eth1):** Next, I confirmed connectivity to my Metasploitable2 VM on the isolated lab network by pinging its IP address (`192.168.117.3`).
        ```bash
        ping 192.168.117.3
        ```
        Successful replies confirmed my Host-Only adapter (`eth1`) was properly connected to the lab network and could communicate with the target.

    Finally, I ran `ip a` to confirm both `eth0` and `eth1` had their expected configurations (though `eth0` lacked an IP when `eth1` was active). This dual verification confirmed Kali was ready for its role as the IDS monitoring station, even with the temporary internet workaround.
    ![Kali Linux Dual Network Verification]![VirtualBox_Kali Linux_29_06_2025_03_30_37](https://github.com/user-attachments/assets/3f4ef7be-f0a5-4014-89ba-b5852bf160a1)
### 1.4. **Temporary Workaround: Disabling Host-Only Adapter for Internet Access**

* **My Action:** Given the observed conflict where Kali's NAT (internet) adapter (`eth0`) loses connectivity when the Host-Only adapter (`eth1`) is active, I adopted a practical workaround. To ensure uninterrupted internet access for essential tasks like updating Suricata rules and downloading necessary files, I decided to temporarily disable Adapter 2 (the Host-Only interface) whenever I specifically needed internet access. Once internet-dependent tasks are complete, I will re-enable Adapter 2 to resume lab monitoring. This approach allows me to manage the VM's connectivity based on the immediate task at hand.

    I powered off the Kali Linux VM. In VirtualBox Manager, I navigated to Kali's Network settings, went to the `Adapter 2` tab, and unchecked `Enable Network Adapter`. After saving the settings, I powered on the Kali VM again. This restored full internet access to `eth0`, allowing me to proceed with Suricata configuration without interruption.

### 2.1. **Configuring Suricata (Editing `suricata.yaml`)**

* **My Action:** The core of Suricata's operation lies in its configuration file, `suricata.yaml`, located in `/etc/suricata/`. This file dictates how Suricata processes traffic, where it logs alerts, and crucially, which network interface it should monitor. I opened this file using `nano` (a command-line text editor), utilizing `Ctrl+W` to quickly navigate to the necessary sections.

    * **Defining `HOME_NET`:** First, I located the `vars` section and the `HOME_NET` variable. This variable is fundamental as it tells Suricata which IP ranges are considered internal to my network. I changed the default broad ranges to specifically include my Host-Only network's subnet, `192.168.117.0/24`. This ensures Suricata correctly identifies internal traffic from my lab.
        ```yaml
        vars:
          # more specific is better for alert accuracy and performance
          address-groups:
            # HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
            HOME_NET: "[192.168.117.0/24]"
            #HOME_NET: "[10.0.0.0/8]" # Original example, commented out.
        ```

    * **Specifying the Monitoring Interface (`af-packet`):** Next, I scrolled down to the `af-packet` section. This tells Suricata which network adapter it should listen on for incoming traffic. I changed the default interface from `eth0` to `eth1`, as `eth1` is my Kali VM's Host-Only adapter, directly connected to my isolated lab network where Metasploitable2 resides. This is the crucial step for Suricata to see all traffic within my lab.
        ```yaml
        # Linux high speed capture support
        af-packet:
          - interface: eth1  # Changed from eth0 to eth1
            # Number of receive threads. "auto" uses the number of cores
            #threads: auto
            # Default clusterid. AF_PACKET will load balance packets based on flow.
            cluster-id: 99
            # ... (other af-packet options) ...
        ```
    After making these changes, I saved the `suricata.yaml` file (`Ctrl+X`, `Y`, Enter). Now, Suricata is properly configured to monitor my lab environment!

* **Screenshot:**
    **Show your Kali Linux terminal displaying the relevant sections of `/etc/suricata/suricata.yaml` open in `nano`, specifically highlighting the `interface: eth1` line (uncommented) within the `af-packet` section and the `HOME_NET` variable set to `[192.168.117.0/24]`.**
    ![Configuring Suricata YAML]![VirtualBox_Kali Linux_29_06_2025_04_03_34](https://github.com/user-attachments/assets/981aaeef-b795-42ab-a70e-5f5ffb1d42a0)
### 2.2. **Updating Suricata Rules**

* **My Action:** With Suricata installed and its primary configuration file (`suricata.yaml`) updated to monitor `eth1` and identify my `HOME_NET`, the next critical step was to ensure Suricata had the latest threat intelligence. Intrusion Detection Systems rely heavily on rule sets (signatures) to identify known malicious patterns in network traffic. To download and enable the freshest rules, I used the `suricata-update` command. Since this requires internet access, I ensured Kali's Adapter 2 (Host-Only) was temporarily disabled, allowing `eth0` (NAT) to connect to the internet.

    ```bash
    sudo suricata-update
    ```
    The command successfully downloaded and compiled the latest rulesets, a process that involved fetching from various sources and then enabling the newly acquired signatures. This crucial step equipped Suricata with the most current knowledge of threats, making it ready to function as an effective network sentinel.

* **Screenshot:**
    **Show your Kali Linux terminal with the output of the `sudo suricata-update` command, confirming the successful rule update.**
    ![Updating Suricata Rules]![VirtualBox_Kali Linux_29_06_2025_04_09_24](https://github.com/user-attachments/assets/4cc2486e-e57a-4f40-b142-ab48baea7663)
  ### 2.3. **Re-enabling Host-Only Adapter & Starting Suricata for Monitoring**

* **My Action:** With Suricata configured and its rules updated, it was time to re-establish full lab connectivity and initiate monitoring. As per my workaround, I powered off the Kali VM again. In VirtualBox Manager, I went back to Kali's Network settings, re-enabled `Adapter 2` (my Host-Only interface), and ensured `Promiscuous Mode` was set to `Allow All`. After saving the settings and booting Kali back up, I confirmed that `eth1` (my Host-Only adapter) was active and had its `192.168.117.x` IP address, enabling communication with Metasploitable2.

    Now, with the monitoring interface online, I could start the Suricata service, instructing it to run in "IDS mode" (Intrusion Detection System) on `eth1`. This command initiates Suricata's traffic inspection and logging.

    ```bash
    sudo suricata -c /etc/suricata/suricata.yaml -i eth1
    ```
    The output confirmed that Suricata version 7.0.10 RELEASE was successfully running in SYSTEM mode, indicating that my IDS was now actively monitoring the `eth1` interface for any suspicious activities within my isolated lab network.

* **Screenshot:**
    **Show your Kali Linux terminal displaying the output of the `sudo suricata -c /etc/suricata/suricata.yaml -i eth1` command, indicating that Suricata has successfully started and is listening on `eth1`.**
    ![Starting Suricata IDS]![VirtualBox_Kali Linux_29_06_2025_04_14_36](https://github.com/user-attachments/assets/88b26b4c-20bb-4384-a603-dae642fb62b9)
  ## 🧪 **Phase 3: Testing Our IDS - Triggering and Verifying Alerts**

With Suricata now actively monitoring my Host-Only network, the next crucial step is to test its detection capabilities. The goal is to generate some "malicious" network traffic from Kali Linux towards Metasploitable2 and observe if Suricata successfully triggers alerts based on its loaded rules. This confirms that my IDS is correctly configured and operational.

### 3.1. **Triggering a Basic ICMP (Ping) Alert**

* **My Action:** A common and simple way to test an IDS is to trigger an alert with basic ICMP (ping) traffic, especially if there's a rule configured to detect it. Many default Suricata rule sets include rules for detecting unusual or excessive ping activity, or even specific ICMP types. To generate this traffic, I opened a *new* terminal window on my Kali Linux VM (leaving the Suricata process running in its original terminal). From this new terminal, I initiated a continuous ping to my Metasploitable2 VM's IP address.

    ```bash
    ping 192.168.117.3
    ```
    This command floods Metasploitable2 with ICMP echo requests, which Suricata, if configured correctly, should flag as suspicious and generate an alert. I let this ping run for a few seconds to ensure enough traffic was generated for detection.

* **Screenshot:**
    **Show your Kali Linux VM desktop with TWO terminal windows open:**
    * **Terminal 1 (Left/Top):** Displaying Suricata running in the foreground (from the previous step, confirming "Suricata version ... running in SYSTEM mode").
    * **Terminal 2 (Right/Bottom):** Displaying the active `ping 192.168.117.3` command to Metasploitable2.
    ![Triggering ICMP Alert]![VirtualBox_Kali Linux_29_06_2025_04_22_28](https://github.com/user-attachments/assets/500c4ebe-d60e-4f89-9794-73e66e036ed4)
![VirtualBox_Kali Linux_29_06_2025_04_26_27](https://github.com/user-attachments/assets/0e1d5e08-2de0-4f8b-94b6-d02ea8196c01)

### 3.2. **Verifying Suricata Alerts**

* **My Action:** After generating the test ICMP traffic from Kali to Metasploitable2, the critical next step was to examine Suricata's logs to confirm that an alert was triggered. Suricata logs various types of information, but alerts (detections of suspicious activity) are typically found in `fast.log` (for a quick, human-readable summary) or `eve.json` (for more detailed, machine-readable JSON output). I opened a *new* terminal window on Kali Linux to view the `eve.json` file, as it provides comprehensive event data. To precisely identify my custom ICMP alerts within the voluminous `eve.json` output, I employed `grep` to filter for the specific message defined in my rule.

    ```bash
    sudo tail -f /var/log/suricata/eve.json
    # (Initially no custom alerts visible in raw tail output)
    sudo cat /var/log/suricata/eve.json | grep "ICMP Ping detected - CUSTOM RULE"
    ```
    As soon as I initiated ping traffic from Kali to Metasploitable2, and then filtered the `eve.json` log with `grep`, the output clearly displayed multiple JSON entries with `"event_type": "alert"` and `"alert":{"signature":"ICMP Ping detected - CUSTOM RULE"`. These alerts accurately identified the source (`192.168.117.4`), destination (`192.168.117.3`), and protocol (`ICMP`) of the ping traffic. This irrefutably verified that Suricata was actively monitoring the `eth1` interface, processing traffic, and successfully generating alerts based on the custom rule I defined. The IDS is fully operational!

    ![Suricata ICMP Alert in Eve Log]![VirtualBox_Kali Linux_29_06_2025_05_28_15](https://github.com/user-attachments/assets/c6299d94-f1cb-46cd-ba15-bcd3977cf22e)
