sr		= 	        44100
kr          	= 	        441
ksmps       	= 	        100
nchnls      	= 	        2

        	instr 1		; single oscillator
idur		=		p3
iamp		=  		p4
icps		=		cpsoct((p5 / 12.0) + 3)
aenv		linen		iamp, 0.01*idur, p3, 0.4*idur
a1		oscili		aenv, icps, 1
		outs		a1, a1
		endin

                instr 2         ; reverb
ain1, ain2      ins
arev11          nreverb         ain1, 1.0, 0.3
arev12          nreverb         arev11, 2.0, 0.5
arev13          nreverb         arev12, 4.0, 0.9
arev21          nreverb         ain2, 1.0, 0.3
arev22          nreverb         arev21, 2.0, 0.5
arev23          nreverb         arev22, 4.0, 0.9
                outs            (arev11+arev12+arev13)*0.1, (arev21+arev22+arev23)*0.1
                endin

; EOF
