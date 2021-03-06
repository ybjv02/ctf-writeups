# Sniffed Traffic

> Author: EnyeiWe inspected our logs and found someone downloading a file from a machine **within the same network**. Can you help find out what the contents of the file are? 
>
> For beginners: https://www.javatpoint.com/wireshark
>
> MD5: `71cd3bdbecece8d7919b586959f2d3b7`
>
> **Attached Files**: forensics.pcapng

Opening `forensics.pcapng` greets us with a substantial amount of packets. Since the description mentioned that the someone downloaded a file, I went to check out `Export Objects -> HTTP` and sure enough, there was a suspicious zip file named `thingamajig.zip`.

![image-20220604201134791](./images/exported-objects.png)

However, opening the zip file shows that it was encrypted. I tried brute-forcing the password using fcrackzip but to no avail. Thus, I dived back into the pcap file to dig for more clues. Fortunately, filtering for the client's IP address(whom requested for the zip file) reveals that there is some plaintext communication going on.

![image-20220604201754191](./images/filter.PNG)

Naturally, I tracked the communication via `Follow -> TCP Stream`, which revealed the password as shown below.

![image-20220604201913375](./images/follow-stream.png)

Extracting the zip file yields the sole file named `stuff`. 

![zip](images/zip.png)

Since the file has no extension, I ran the `binwalk` on it, which showed that the file was contained a zip archive.

![image-20220604203942679](./images/binwalk.png)

After extracting the zip file & adding the .zip extension, there was yet again another password prompt. This time however, `fcrackzip` worked, revealing the password `john`. Extracting the zip archive will yield the file `flag.txt` which contains the flag.

Flag: SEE{w1r35haRk_d0dod0_4c87be4cd5e37eb1e9a676e110fe59e3}
