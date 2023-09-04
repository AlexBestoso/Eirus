# Eirus
An application that I'm using for studying the Elf binary format and parasitic malware development.
<br>
<br>
Run `make` and the program will compile the `erius` binary, the `victim` binary, and a sample `payload` binary.<br>
<br>
To infect the `victim` program with the `payload` malware, simply run `./eirus payload victim` and the application will inject you payload in to the victim's .text section of the elf file.<br>
<br>
As of now this software <b><i>Just Works</i></b>. And I guarentee nothing with it. Including wheather or not people will abuse it.<br>
<br>
I call it Eirus because it can be used to make Elf Viruses...<i>Alegidly</i>...
