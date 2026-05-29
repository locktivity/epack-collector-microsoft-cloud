package collector

import "math"

func PercentInt(numerator, denominator int) *int {
	if denominator <= 0 {
		return nil
	}
	return PercentFloat(float64(numerator), float64(denominator))
}

func PercentFloat(numerator, denominator float64) *int {
	if denominator <= 0 {
		return nil
	}
	value := int(math.Round((numerator / denominator) * 100))
	if value < 0 {
		value = 0
	}
	if value > 100 {
		value = 100
	}
	return &value
}
