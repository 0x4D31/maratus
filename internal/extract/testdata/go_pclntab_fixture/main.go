package main

import "fmt"

func analystVisibleHelper(value int) string {
	return fmt.Sprintf("fixture-%d", value)
}

func main() {
	fmt.Println(analystVisibleHelper(7))
}
