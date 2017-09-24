#include "enigma.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define BLOCK_SIZE 5
#define END_BLOCK(x) ((x)%BLOCK_SIZE == 0)

int g_verbose = 0;
char *g_settings = NULL;

void
usage( void ) {
	printf("usage: enigma [-s SETTINGS] FILE\n");
	printf("\n");
	printf("Enigma Arguments:\n");
	printf("\t-s Initialize enigma using SETTINGS file\n");
	printf("\t-v Verbose output\n");
	printf("\t-h Display this help message\n");
	exit(1);
}

void 
parse_args ( int argc, char *argv[] ) {    
    int c;

    opterr = 0;

    while( (c = getopt (argc, argv, "vhs:")) != -1 ) {
        switch (c) {        
        case 'v':
            g_verbose = 1;
            break;
        case 's':
            g_settings = optarg;
            break;
        case 'h':
            usage();
        case '?':
            if (optopt == 'c'){
                fprintf(stderr, "Option -%c requires an argument.\n", optopt);
            } else if (isprint (optopt)) {
                fprintf(stderr, "Unknown option `-%c'.\n", optopt);
            } else {
                fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
            }
        default:
            exit(1);
        }
    }
}

void
initialize( int argc, char *argv[] ) {

	parse_args ( argc, argv );

	if( optind == argc ) {
		usage();
	}

	enigma_init();
	
	if(g_settings) {
		enigma_state_load(g_settings);
	}

	if(g_verbose) {
		enigma_print();
	}
}

void
encrypt( char *fname ) {
	FILE *f;
	char c;
	int i=0;

	f= fopen(fname, "r");
	if(!f) {
		printf("Unable to open %s\n", fname);
		exit(1);
	}

	while( !feof(f) ) {
		c=fgetc(f);		
		if( isalpha(c) ) {
			printf( "%c", enigma_encode(c) );			
			if(END_BLOCK(++i)) { printf(" "); }						
		}
	}
	
	printf("\n");
    fclose(f);
}

int
main( int argc, char *argv[] ) {
	
	initialize( argc, argv );	
	encrypt( argv[optind] );
	enigma_state_save("settings.conf");
    return EXIT_SUCCESS;
}