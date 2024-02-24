package utils

func (x *ECPoint) ValidateBasic() bool {
	return x != nil && NonEmptyBytes(x.GetX()) && NonEmptyBytes(x.GetY())
}
