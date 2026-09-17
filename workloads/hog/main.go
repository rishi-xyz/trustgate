// hog allocates far more memory than allowed; used to test the memory limit.
package main

import "fmt"

func main() {
	b := make([]byte, 512<<20)
	for i := range b {
		b[i] = byte(i)
	}
	fmt.Println(len(b))
}
