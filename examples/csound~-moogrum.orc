sr		=		44100
kr		=		441
ksmps		=		100
nchnls		=		1

gkcut		init		0			; filter cutoff
gkres		init		0			; filter resonance

		instr 1					; moog vc filter
ain		in
aout		moogvcf		ain, gkcut, gkres
		out		aout
		endin

		instr 2					;  control
gkcut		=		p4
gkres		=		p5
		endin

; EOF
