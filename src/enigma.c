#include "enigma.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RACK_SIZE   4
#define MAX_NOTCHES 2
#define MAP_SIZE    26
#define BUF_MAX     32

#define DECODE(x)((x)+'A') // index to letter
#define ENCODE(x)((x)-'A') // letter to index
#define IS_VALID(x)(((x)>=0) && ((x)<MAP_SIZE)) // check if x can be encrypted

struct encrypter {
    int rotation, ringset, num_notches, code;
    int notches[MAX_NOTCHES];   
    char map[MAP_SIZE];  // input to output map (for forward pass)
    char inv[MAP_SIZE];  // output to input maps (for backward pass)
};

static struct encrypter rotors[] = {
    // Rotor I
    { .rotation=0, .ringset=0, .num_notches=1, .notches={16}, .code=ROTOR_I,
        .map="EKMFLGDQVZNTOWYHXUSPAIBRCJ", .inv="UWYGADFPVZBECKMTHXSLRINQOJ" },
    // Rotor II
    { .rotation=0, .ringset=0, .num_notches=1, .notches={4}, .code=ROTOR_II,
        .map="AJDKSIRUXBLHWTMCQGZNPYFVOE", .inv="AJPCZWRLFBDKOTYUQGENHXMIVS" },
    // Rotor III
    { .rotation=0, .ringset=0, .num_notches=1, .notches={21}, .code=ROTOR_III,
        .map="BDFHJLCPRTXVZNYEIWGAKMUSQO", .inv="TAGBPCSDQEUFVNZHYIXJWLRKOM" },
    // Rotor IV
    { .rotation=0, .ringset=0, .num_notches=1, .notches={9}, .code=ROTOR_IV,
        .map="ESOVPZJAYQUIRHXLNFTGKDCMWB", .inv="HZWVARTNLGUPXQCEJMBSKDYOIF" },
    // Rotor V
    { .rotation=0, .ringset=0, .num_notches=1, .notches={25}, .code=ROTOR_V,
        .map="VZBRGITYUPSDNHLXAWMJQOFECK", .inv="QCYLXWENFTZOSMVJUDKGIARPHB" },
    // Rotor VI
    { .rotation=0, .ringset=0, .num_notches=2, .notches={25,12}, .code=ROTOR_VI,
        .map="JPGVOUMFYQBENHZRDKASXLICTW", .inv="SKXQLHCNWARVGMEBJPTYFDZUIO" },
    // Rotor VII
    { .rotation=0, .ringset=0, .num_notches=2, .notches={25,12}, .code=ROTOR_VII,
        .map="NZJHGRCXMYSWBOUFAIVLPEKQDT", .inv="QMGYVPEDRCWTIANUXFKZOSLHJB" },
    // Rotor VIII
    { .rotation=0, .ringset=0, .num_notches=2, .notches={25,12}, .code=ROTOR_VIII,
        .map="FKQHTLXOCBJSPDZRAMEWNIUYGV", .inv="QJINSAYDVKBFRUHMCPLEWZTGXO" },
    // Rotor b (beta)
    { .rotation=0, .ringset=0, .num_notches=0, .code=ROTOR_B,
        .map="LEYJVCNIXWPBQMDRTAKZGFUHOS", .inv="RLFOBVUXHDSANGYKMPZQWEJICT" },
    // Rotor g (gamma)
    { .rotation=0, .ringset=0, .num_notches=0, .code=ROTOR_G,
        .map="FSOKANUERHMBTIYCWLQPZXVGJD", .inv="ELPZHAXJNYDRKFCTSIBMGWQVOU" }
};

// On the physical machine, the reflector would sit at the end of the rack and 
// **reflect** the electrical impulse representing the encoded character back through
// the series of rotors in the rack.
static struct encrypter reflectors[] = {
    { .map = "YRUHQSLDPXNGOKMIEBFZCWVJAT", .code=REFLECTOR_B },      // M3 B
    { .map = "FVPJIAOYEDRZXWGCTKUQSBNMHL", .code=REFLECTOR_C },      // M3 C
    { .map = "ENKQAUYWJICOPBLMDXZVFTHRGS", .code=REFLECTOR_B_THIN }, // M4 B thin
    { .map = "RDOBJNTKVEHMLFCWZAXGYIPSUQ", .code=REFLECTOR_C_THIN }, // M4 C thin
};

// The plugboard was used by the enigma operator to specifically wire an input/output
// to a different value before and after it hit the rack. By default every character in
// the plugboard maps to itself.
static struct encrypter plugboard = { .map = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" };

// Rotor configurations in the rack. Note that the rotor in the fourth position is only 
// used if we are in MODE_M4
static struct encrypter rack[RACK_SIZE]; // Sequence of rotors to be used for encryption
static struct encrypter reflector;       // Index of chosen reflector
static int mode = MODE_M3;               // Type of Enigma machine being emulated
static int num_rotors = 3;               // Number of rotors in the rack (mode dependent)

static int
offset( struct encrypter *e, int c ) {
    c = (MAP_SIZE + (c - e->ringset))%MAP_SIZE;  // ringset offset - negative modulus
    return (c + e->rotation)%MAP_SIZE;           // rotation offset
}

static int
undo_offset( struct encrypter *e, int c ) {
    c = (MAP_SIZE + (c - e->rotation))%MAP_SIZE; // undo rotation offset - neg modulo
    return (c+e->ringset)%MAP_SIZE;              // undo ringset offset
}

static int
inv_crypt ( struct encrypter *e, int c ) {
    c = offset(e,c);         // offset for rotation and ringset
    c = ENCODE(e->inv[c]);   // crypt
    return undo_offset(e,c); // undo offset for rotation and ringset
}

static int
crypt ( struct encrypter *e, int c ) {
    c = offset(e,c);         // offset for rotation and ringset
    c = ENCODE(e->map[c]);   // crypt
    return undo_offset(e,c); // undo offset for rotation and ringset
}

static int
is_notched( struct encrypter *e ) {
    int i;
    for( i=0; i<e->num_notches; i++ ) { if(e->notches[i]==e->rotation) return 1; }
    return 0;
}

static void
spin_rotors ( void ) {
    // check if rotor 2 is in the notch position
    if(is_notched(&rack[1])){
        // if so, rotate rotors 2 and 3 forwards, implementing double stepping
        rack[1].rotation = (++rack[1].rotation)%MAP_SIZE;
        rack[2].rotation = (++rack[2].rotation)%MAP_SIZE;
    }

    // if rotor 1 is in the notched position, rotate rotor 2 forwards
    if(is_notched(&rack[0]))
        rack[1].rotation = (++rack[1].rotation)%MAP_SIZE;

    // rotor 1 always rotates.
    rack[0].rotation = (++rack[0].rotation)%MAP_SIZE;
}

void
enigma_init ( void ) {    
    enigma_load_rotor(0, ROTOR_III);
    enigma_load_rotor(1, ROTOR_II);
    enigma_load_rotor(2, ROTOR_I);
    enigma_load_rotor(3, ROTOR_B);
    enigma_load_reflector( REFLECTOR_B );
    enigma_set_mode(MODE_M3);
}

char
enigma_encode ( char c ) {
    int i;
    char ec = ENCODE(toupper(c));
    
    if( IS_VALID(ec) ) {
        // first, rotors spin on key press
        spin_rotors();
        // letter passes through plugboard
        ec = crypt( &plugboard, ec );
        // then through each of the rotors in turn
        for(i=0; i<num_rotors; i++){ ec = crypt( &rack[i], ec); }
        // bounce through the reflector
        ec = crypt( &reflector, ec);
        // back through the rotors in the opposite direction
        for(--i; i>=0; i--){ ec = inv_crypt( &rack[i], ec); }
        // lastly, through the plugboard again
        ec = crypt( &plugboard, ec ); 
        // get the encrypted letter as a char
        c = DECODE(ec);
    }

    return c; // return encrypted letter or original symbol if not valid for encryption
}

void
enigma_plugboard_map ( char a, char b ) {
    int tmp, ea, eb;
    a = toupper(a); b = toupper(b); // upper case inputs
    ea = ENCODE(a); eb = ENCODE(b); // convert ASCII codes to zeroed indexes

    if( IS_VALID(ea) && IS_VALID(eb) ) {        
        // remove any existing connections which a and b might have
        if( (tmp=crypt(&plugboard, ea)) != ea ) { plugboard.map[tmp] = DECODE(tmp); }
        if( (tmp=crypt(&plugboard, eb)) != eb ) { plugboard.map[tmp] = DECODE(tmp); }

        // wire a to b and vice versa
        plugboard.map[ea] = b;
        plugboard.map[eb] = a;
    }
}

void
enigma_load_rotor ( int slot, int rotor ) {
    if( (rotor >= ROTOR_B && slot == (RACK_SIZE-1)) || 
        (rotor < ROTOR_B && slot < (RACK_SIZE-1) ) ) {
        rack[slot] = rotors[rotor];
    } 
}

void
enigma_set_rotation ( int slot, int rotation ) {
    rotation = (MAP_SIZE + rotation%MAP_SIZE)%MAP_SIZE;
    rack[slot].rotation = rotation;
}

void
enigma_set_ringset ( int slot, int ringset ) {
    ringset = (MAP_SIZE + ringset%MAP_SIZE)%MAP_SIZE;
    rack[slot].ringset = ringset;
}

void
enigma_load_reflector ( int ref ) {
    if( (mode && ref >= REFLECTOR_B_THIN) || ( !mode && ref < REFLECTOR_B_THIN  ) ) {
        reflector = reflectors[ref];
    }
}

void
enigma_set_mode ( int m ) {
    if( m>=0 && m<=MODE_M4 ) {
        mode = m;
        switch(mode) {
        case MODE_M3:
            num_rotors = 3;
            if( reflector.code > REFLECTOR_C ) {
                reflector = reflectors[reflector.code-REFLECTOR_B_THIN];
            }
            break;
        case MODE_M4:            
            num_rotors = 4;
            if( reflector.code < REFLECTOR_B_THIN ) {
                reflector = reflectors[reflector.code+REFLECTOR_B_THIN];
            }
            break;
        }
    }    
}

//=====================================================================================
//
// Everything past this point is just utilities for I/O and other boring stuff.
//
//=====================================================================================

void
enigma_state_save ( char *fname ) {
    FILE *f;
    int i;

    f = fopen(fname, "w");
    if(!f) {
        fprintf(stderr, "Unable to open %s\n", fname);
        return;
    }

    fprintf(f, "#==================================================================\n");
    fprintf(f, "# ENIGMA MACHINE SETTINGS\n"                                          );
    fprintf(f, "#==================================================================\n");    
    fprintf(f, "# This file describes the initial state of the enigma machine. You\n" );
    fprintf(f, "# may share this file with an individual who needs to decrypt your\n" );
    fprintf(f, "# messages. You should not let this file fall into the hands of\n"    );
    fprintf(f, "# anyone who does not have permission to read your messages\n"        );
    fprintf(f, "# \n"                                                                 );
    fprintf(f, "# This file is parsed sequentially, so the order in which you place\n");
    fprintf(f, "# the entries matters. If a future setting would invalidate an \n"    );
    fprintf(f, "# earlier one, then it will either be ignored or the earlier entry\n" );
    fprintf(f, "# will be reset to keep the enigma machine in a valid state.\n"       );
    fprintf(f, "# \n"                                                                 );
    fprintf(f, "# Generally speaking, the operation mode has highest priority. If a\n");
    fprintf(f, "# choice of mode invalidates a rotor/reflector setting, then the\n"   );
    fprintf(f, "# offending rotor will be set to some suitable default. However, if\n");
    fprintf(f, "# a future rotor/reflector setting is incompatible with the current\n");
    fprintf(f, "# operational mode, then the rotor will be ignored. For the\n"        );
    fprintf(f, "# plugboard, future mappings always take priority over older ones.\n" );
    fprintf(f, "#==================================================================\n");
    fprintf(f, "\n"                                                                   );
    fprintf(f, "#------------------------------------------------------------------\n");
    fprintf(f, "# OPERATIONAL SETTINGS\n"                                             );
    fprintf(f, "#------------------------------------------------------------------\n");
    fprintf(f, "# These settings control some of the basic ways in which the enigma\n");
    fprintf(f, "# machine will behave. At the moment, the only operational setting \n");
    fprintf(f, "# is the mode.                                                     \n");
    fprintf(f, "#\n"                                                                  );
    fprintf(f, "# Values:                                                          \n");
    fprintf(f, "#     - mode=0 [emulates M3 engima with three rotors]              \n");
    fprintf(f, "#     - mode=1 [emulates M4 engima with four rotors]               \n");
    fprintf(f, "#------------------------------------------------------------------\n");    
    fprintf(f, "mode=%d\n", mode                                                      );
    fprintf(f, "\n"                                                                   );
    fprintf(f, "#------------------------------------------------------------------\n");
    fprintf(f, "# RACK SETTINGS\n"                                                    );
    fprintf(f, "#------------------------------------------------------------------\n");
    fprintf(f, "# The rack settings determine which rotors and reflectors are used \n");
    fprintf(f, "# for encryption, as well as their initial state.                  \n");
    fprintf(f, "# \n"                                                                 );
    fprintf(f, "# A rotor configuration is comprised of four parts. First, rN where\n");
    fprintf(f, "# N is the index of the rotor in the rack (a value between 0 and 3.\n");
    fprintf(f, "# After the equals sign there are three values: the rotor code, the\n");
    fprintf(f, "# rotors starting offset (a value between 0 and 25) and the ring\n"   );
    fprintf(f, "# settings (also a value between 0 and 25. To give an example, the\n" );
    fprintf(f, "# entry below is the equivalent of setting the first rotor in the \n" );
    fprintf(f, "# rack to Rotor I with a starting offset of 6 and a ringset of 3 \n"  );
    fprintf(f, "#     r0=0 6 3\n"                                                     );
    fprintf(f, "# \n"                                                                 );
    fprintf(f, "# Values for the Rotor are:\n"                                        );
    fprintf(f, "#     - 0 [Rotor I]\n"                                                );
    fprintf(f, "#     - 1 [Rotor II]\n"                                               );
    fprintf(f, "#     - 2 [Rotor III]\n"                                              );
    fprintf(f, "#     - 3 [Rotor IV]\n"                                               );
    fprintf(f, "#     - 4 [Rotor V]\n"                                                );
    fprintf(f, "#     - 5 [Rotor VI]\n"                                               );
    fprintf(f, "#     - 6 [Rotor VII]\n"                                              );
    fprintf(f, "#     - 7 [Rotor VIII]\n"                                             );
    fprintf(f, "#     - 8 [Rotor b (beta)]\n"                                         );
    fprintf(f, "#     - 9 [Rotor g (gamma)]\n"                                        );
    fprintf(f, "#\n"                                                                  );
    fprintf(f, "# The reflector can simply be set to the code of the reflector you \n");
    fprintf(f, "# want to use. \n"                                                    );
    fprintf(f, "# \n"                                                                 );
    fprintf(f, "# Values for the Reflector are:\n"                                    );
    fprintf(f, "#     - 0 [Reflector B (mode M3 only)]\n"                             );
    fprintf(f, "#     - 1 [Reflector C (mode M3 only)]\n"                             );
    fprintf(f, "#     - 2 [Reflector B Thin (mode M4 only)]\n"                        );
    fprintf(f, "#     - 3 [Reflector C Thin (mode M4 only)]\n"                        );
    fprintf(f, "#------------------------------------------------------------------\n");    
    for( i=0; i<num_rotors; i++ ) {
        fprintf(f, "r%d=%d %d %d\n", i, rack[i].code, rack[i].rotation, 
            rack[i].ringset);
    }
    fprintf(f, "reflector=%d\n", reflector.code                                       );
    fprintf(f, "\n");
    fprintf(f, "#------------------------------------------------------------------\n");
    fprintf(f, "# PLUGBOARD MAPPINGS\n"                                               );
    fprintf(f, "#------------------------------------------------------------------\n");
    fprintf(f, "# Mapping is symmetric, i.e. if C=A then A=C. The tool which\n"       );
    fprintf(f, "# generated this file does not remove duplicates, so every entry is\n");
    fprintf(f, "# in here twice (once for C=A and once for A=C). Make sure you\n"     );
    fprintf(f, "# delete both if you are rewiring. You only need to input a mapping\n");
    fprintf(f, "# once and the enigma machine will handle the symmetry (so just \n"   );
    fprintf(f, "# writing A=C is enough to create both A=C and C=A mapping).\n"       );
    fprintf(f, "#------------------------------------------------------------------\n");        
    for( i=0; i<MAP_SIZE; i++ ) {
        if( plugboard.map[i] != DECODE(i) ) {
            fprintf(f, "%c=%c\n", DECODE(i), plugboard.map[i]);
        }
    }
    fclose(f);
}

void
enigma_state_load ( char *fname ) {    
    FILE *f;
    int i,c,x,y,z;
    char buf[BUF_MAX] = {0};

    f = fopen(fname, "r");
    if(!f) {
        fprintf(stderr, "Unable to open %s\n", fname);
        return;
    }

    while(!feof(f)) {
        i=0; c=0;
        for(;;) {
            buf[i] = fgetc(f);
            if(feof(f)||buf[i]=='\n') { break; }
            if(buf[i]=='#') { c=1; }
            if(++i >= BUF_MAX || c) { --i; } 
        }
        buf[i] = 0;
        if(i) {
            switch(buf[0]) {
                case 'm':                    
                    if(!strncmp( buf, "mode", 4 )) {
                        sscanf(&buf[4], "=%d", &x);                        
                        enigma_set_mode(x);
                    }
                    break;
                case 'r':
                    if(!strncmp( buf, "reflector", 9 )) {
                        sscanf(&buf[9], "=%d", &x);                        
                        enigma_load_reflector(x);
                    } else {
                        sscanf(&buf[3], "%d %d %d", &x, &y, &z);
                        enigma_load_rotor(buf[1]-'0', x);
                        enigma_set_rotation(buf[1]-'0', y);
                        enigma_set_ringset(buf[1]-'0', z);

                    }
                    break;
                default:
                    enigma_plugboard_map(buf[0],buf[2]);                
            }
        }
    }

    fclose(f);
}

void
enigma_print ( void ) {
    static char *reflector_strings[] = { "B", "C", "Bt", "Ct" };
    static char *rotor_strings[] = {
        " I ", " II", "III", " IV", " V ", " VI", "VII", "VIII", "b", "g"
    };
    
    int i;
    printf("====================\n");
    printf("ENIGMA CONFIGURATION\n");
    printf("====================\n\n");
    printf("Mode: %s\n\n", (mode)? "M4" : "M3");
    printf("Rack:\n");
    printf(" Ref %s   R3      R2      R1   \n", (mode)? "  R4   ":"");
    printf(" --- %s  -----   -----   ----- \n",(mode)? "  --- ":"");
    
    printf("|%2s | ", reflector_strings[reflector.code]);
    if(mode) {
        printf("| %s | ", rotor_strings[rack[3].code]);
    }
    printf("| %3s | | %3s | | %3s | <- wheel code\n", 
            rotor_strings[rack[2].code],
            rotor_strings[rack[1].code],
            rotor_strings[rack[0].code]
        );

    printf("|   | ");
    if(mode) {
        printf("| %c | ", DECODE(rack[3].rotation));
    }
    printf("|  %c  | |  %c  | |  %c  | <- ground setting\n", 
            DECODE(rack[2].rotation),
            DECODE(rack[1].rotation),
            DECODE(rack[0].rotation)
        );

    printf("|   | ");
    if(mode) {
        printf("|%2d | ", rack[3].ringset);
    }
    printf("| %2d  | | %2d  | | %2d  | <- ring setting\n", 
            rack[2].ringset,
            rack[1].ringset,
            rack[0].ringset
        );
    
    printf(" --- %s  -----   -----   ----- \n",(mode)? "  --- ":"");    
    printf("\n");
    printf("Plugboard:\n\t");
    for( i=0; i<MAP_SIZE; i++ ) {
        printf("%c", DECODE(i));
    }
    printf("\n\t");
    for( i=0; i<MAP_SIZE; i++ ) {
        printf("|");
    }
    printf("\n\t");
    for( i=0; i<MAP_SIZE; i++ ) {
        printf("%c", plugboard.map[i]);
    }
    printf("\n");
}