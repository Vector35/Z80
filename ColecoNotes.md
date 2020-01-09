## ColecoVision Mem Map

```
[0000, 2000) - BIOS ROM
[2000, 4000) - Expansion Port
[4000, 6000) - Expansion Port
[6000, 8000) - RAM (1K mapped into 8K)
[8000, FFFF] - Cartridge ROM (32K 4 sections, enabled separately)
```

## ROM Header

```
[8000, 8002) - AA 55 or AA 55
[8002, 8004) - pointer to sprites table (NULL or 0x7XXX)
[8004, 8006) - pointer to sprites table (NULL or 0x7XXX)
[8006, 8008) - pointer to RAM space (NULL or 0x7XXX)
[8008, 800A) - pointer to joysticks (NULL or 0x7XXX)
[800A, 800C) - start address for game
[800C, 800F) - jump to RST 0x08
[800F, 8012) - jump to RST 0x10
[8012, 800C) - jump to RST 0x18
[8015, 800C) - jump to RST 0x20
[8018, 800C) - jump to RST 0x28
[801B, 800C) - jump to RST 0x30
[801E, 800C) - jump to RST 0x38
[8021, 800C) - jump to NMI (vertical retrace interrupt)
[8024, ????) - title screen data
```

## Controllers

Cartridge puts a pointer at 0x8008 so that when it calls POLLER() (0x1FEB) the pointer will be filled with:

```
+0 PLAYER1	; settings
+1 PLAYER2
+2 FIRE1	; fire button 1 (40h=yes, 0=no)
+3 JOY1		;1=N, 2=E, 4=S, 8=W, etc.
+4 SPIN1	;counter
+5 ARM1		;Arm button 1 (40h=yes, 0=no)
+6 KEYPAD1	;0-9, '*'=10, '#'=11
+7 FIRE2	
+8 JOY2	
+9 SPIN2	
+A ARM2
+B KEYPAD2
```

Where settings are (CONTROLLER_ENABLE, KEYPAD_ENABLE, ARM_BUTTON_ENABLE, JOYSTICK_ENABLE, FIRE_BUTTON_ENABLE) = (1,2,8,0x10,0x80).

# References

http://www.colecoboxart.com/faq/FAQ05.htm

http://www.gooddealgames.com/articles/ColecoProgramming/cv%20programming.pdf

