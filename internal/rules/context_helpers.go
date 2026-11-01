package rules

import (
	"sort"
)

func uniqueSortedStrings(values []string) []string {
	values = unique(values)
	sort.Strings(values)
	return values
}
