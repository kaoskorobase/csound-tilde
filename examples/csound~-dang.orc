sr          	= 		44100
kr          	= 		441
ksmps       	= 		100
nchnls      	= 		1

		instr 1		; plucked string
idur		=		p3
icps		=		p4
aenv		expon		1, idur, 0.0001
aout		pluck		1, icps, icps, 0, 1
		out		aenv*aout
		endin

; EOF
