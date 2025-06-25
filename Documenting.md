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

* **Screenshot:**
    **Show your web browser displaying the Metasploitable2 download page (on SourceForge), or a file explorer window clearly showing the unzipped `metasploitable-linux-2.0.0.vmdk` file in your file system, confirming it's ready for import.**
    ![Metasploitable2 Download Page or Unzipped VMDK](YOUR_SCREENSHOT_URL_HERE)
