#ifndef ENIGMA_H
#define ENIGMA_H

// operational modes
enum { MODE_M3, MODE_M4 };

// encryption rotors to be placed in the rack. ROTORA_A and ROTOR_B can only go in the
// fourth rack position and are only used if we are in MODE_M4
enum { ROTOR_I, ROTOR_II, ROTOR_III, ROTOR_IV, ROTOR_V, ROTOR_VI, ROTOR_VII, ROTOR_VIII, 
	ROTOR_B, ROTOR_G };

// reflectors which sit at the end of the rack and bounce signal back through rotors.
// MODE_M4 uses thin reflectors. MODE_M3 uses regular reflectors.
enum { REFLECTOR_B, REFLECTOR_C, REFLECTOR_B_THIN, REFLECTOR_C_THIN };

void enigma_init ( void );
char enigma_encode( char c );
void enigma_plugboard_map( char a, char b );
void enigma_load_rotor ( int slot, int rotor );
void enigma_set_rotation ( int slot, int rotation );
void enigma_set_ringset ( int slot, int ringset );
void enigma_load_reflector ( int ref );
void enigma_set_mode( int m );

void enigma_state_save( char *fname );
void enigma_state_load( char *fname );
void enigma_print( void );

#endif