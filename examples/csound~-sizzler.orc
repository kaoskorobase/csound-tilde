sr		= 		44100
kr          	= 		441
ksmps       	= 		100
nchnls      	= 		2

        	instr 1		; single oscillator panned instrument
idur		=		p3
iamp		=  		p4
icps		=		cpsoct((p5 / 12.0) + 3)
ipan		=		p6
aenv		linen		iamp, 0.01*idur, p3, 0.4*idur
a1		oscili		aenv, icps, 1
		outs		a1 * (1 - ipan), a1 * ipan
		endin

; EOF