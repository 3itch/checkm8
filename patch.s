	.file	"patch.c"
	.text
	.globl	serial_putc
	.type	serial_putc, @function
serial_putc:
	push	%ebp
	movl	%esp, %ebp
	subl	$20, %esp
	movl	8(%ebp), %eax
	movb	%al, -20(%ebp)
	movl	$1016, -4(%ebp)
	nop
.L2:
	movl	-4(%ebp), %eax
	movb	(%eax), %al
	movzbl	%al, %eax
	andl	$32, %eax
	testl	%eax, %eax
	je	.L2
	movb	-20(%ebp), %dl
	movl	-4(%ebp), %eax
	movb	%dl, (%eax)
	nop
	leave
	ret
	.size	serial_putc, .-serial_putc
	.globl	serial_print
	.type	serial_print, @function
serial_print:
	push	%ebp
	movl	%esp, %ebp
	jmp	.L4
.L5:
	movl	8(%ebp), %eax
	leal	1(%eax), %edx
	movl	%edx, 8(%ebp)
	movb	(%eax), %al
	movsbl	%al, %eax
	push	%eax
	call	serial_putc
	addl	$4, %esp
.L4:
	movl	8(%ebp), %eax
	movb	(%eax), %al
	testb	%al, %al
	jne	.L5
	nop
	nop
	leave
	ret
	.size	serial_print, .-serial_print
	.section	.rodata
.LC1:
	.string	"0x"
.LC0:
	.string	"0123456789ABCDEF"
	.text
	.globl	serial_print_hex
	.type	serial_print_hex, @function
serial_print_hex:
	push	%ebp
	movl	%esp, %ebp
	push	%edi
	push	%esi
	push	%ebx
	subl	$32, %esp
	leal	-33(%ebp), %eax
	movl	$.LC0, %ebx
	movl	$17, %edx
	movl	%eax, %edi
	movl	%ebx, %esi
	movl	%edx, %ecx
	rep; movsb
	push	$.LC1
	call	serial_print
	addl	$4, %esp
	movl	$28, -16(%ebp)
	jmp	.L7
.L8:
	movl	-16(%ebp), %eax
	movl	8(%ebp), %edx
	movb	%al, %cl
	shrl	%cl, %edx
	movl	%edx, %eax
	andl	$15, %eax
	movb	-33(%ebp,%eax), %al
	movsbl	%al, %eax
	push	%eax
	call	serial_putc
	addl	$4, %esp
	subl	$4, -16(%ebp)
.L7:
	cmpl	$0, -16(%ebp)
	jns	.L8
	nop
	nop
	leal	-12(%ebp), %esp
	pop	    %ebx
	pop	    %esi
	pop	    %edi
	pop	    %ebp
	ret
	.size	serial_print_hex, .-serial_print_hex
	.section	.rodata
	.align 4
.LC2:
	.string	"checkmate:  patching verify_integrity @ "
.LC3:
	.string	"\n"
.LC4:
	.string	"checkmate:      patched!"
	.text
	.globl	patch
	.type	patch, @function
patch:
	push	%ebp
	movl	%esp, %ebp
	subl	$16, %esp
	movl	$9482000, -8(%ebp)
	push	$.LC2
	call	serial_print
	addl	$4, %esp
	movl	-8(%ebp), %eax
	push	%eax
	call	serial_print_hex
	addl	$4, %esp
	push	$.LC3
	call	serial_print
	addl	$4, %esp
	movl	$440, -14(%ebp)
	movw	$-15616, -10(%ebp)
	movl	$0, -4(%ebp)
	jmp	.L10
.L11:
	movl	-8(%ebp), %edx
	movl	-4(%ebp), %eax
	addl	%eax, %edx
	leal	-14(%ebp), %ecx
	movl	-4(%ebp), %eax
	addl	%ecx, %eax
	movb	(%eax), %al
	movb	%al, (%edx)
	incl	-4(%ebp)
.L10:
	cmpl	$5, -4(%ebp)
	jbe	.L11
	push	$.LC4
	call	serial_print
	addl	$4, %esp
	nop
	leave
	ret
	.size	patch, .-patch
	.section	.rodata
	.align 4
.LC5:
	.string	"checkmate:  tboot base address @ "
	.align 4
.LC6:
	.string	"checkmate:      jumping to tboot entry"
	.text
	.globl	shim_main
	.type	shim_main, @function
shim_main:
	push	%ebp
	movl	%esp, %ebp
	subl	$24, %esp
	push	$.LC5
	call	serial_print
	addl	$4, %esp
	push	$1048576
	call	serial_print_hex
	addl	$4, %esp
	push	$.LC3
	call	serial_print
	addl	$4, %esp
	call	patch
	push	$.LC6
	call	serial_print
	addl	$4, %esp
	movl	$1048576, -12(%ebp)
	movl	-12(%ebp), %eax
	jmp 	*%eax
	nop
	leave
	ret
	.size	shim_main, .-shim_main
	.ident	"GCC: (GNU) 12.2.0"
