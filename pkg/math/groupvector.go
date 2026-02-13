package math

import (
	"fmt"
	"math/big"
	"runtime"
	"sync"
)

// GqVector is a vector of GqElements from the same group.
type GqVector struct {
	elements []GqElement
	group    *GqGroup
}

// NewGqVector creates a new GqVector, validating all elements are from the same group.
func NewGqVector(elements []GqElement) (*GqVector, error) {
	if len(elements) == 0 {
		return &GqVector{elements: []GqElement{}}, nil
	}
	group := elements[0].group
	for i, e := range elements {
		if !e.group.Equals(group) {
			return nil, fmt.Errorf("element %d is from a different group", i)
		}
	}
	copied := make([]GqElement, len(elements))
	copy(copied, elements)
	return &GqVector{elements: copied, group: group}, nil
}

// GqVectorOf creates a GqVector from variadic elements (no validation).
func GqVectorOf(elements ...GqElement) *GqVector {
	if len(elements) == 0 {
		return &GqVector{elements: []GqElement{}}
	}
	copied := make([]GqElement, len(elements))
	copy(copied, elements)
	return &GqVector{elements: copied, group: elements[0].group}
}

// GqVectorFromBigInts creates a GqVector from big.Int values in the given group.
func GqVectorFromBigInts(values []*big.Int, group *GqGroup) (*GqVector, error) {
	elements := make([]GqElement, len(values))
	for i, v := range values {
		e, err := NewGqElement(v, group)
		if err != nil {
			return nil, fmt.Errorf("element %d: %w", i, err)
		}
		elements[i] = e
	}
	return &GqVector{elements: elements, group: group}, nil
}

// GqVectorOfIdentities creates a vector of identity elements.
func GqVectorOfIdentities(size int, group *GqGroup) *GqVector {
	elements := make([]GqElement, size)
	for i := range elements {
		elements[i] = group.Identity()
	}
	return &GqVector{elements: elements, group: group}
}

// Size returns the number of elements.
func (v *GqVector) Size() int {
	return len(v.elements)
}

// Get returns the element at index i.
func (v *GqVector) Get(i int) GqElement {
	return v.elements[i]
}

// Group returns the common group.
func (v *GqVector) Group() *GqGroup {
	return v.group
}

// Elements returns a copy of the elements slice.
func (v *GqVector) Elements() []GqElement {
	copied := make([]GqElement, len(v.elements))
	copy(copied, v.elements)
	return copied
}

// Append creates a new vector with the element appended.
func (v *GqVector) Append(e GqElement) *GqVector {
	newElems := make([]GqElement, len(v.elements)+1)
	copy(newElems, v.elements)
	newElems[len(v.elements)] = e
	group := v.group
	if group == nil {
		group = e.group
	}
	return &GqVector{elements: newElems, group: group}
}

// Prepend creates a new vector with the element prepended.
func (v *GqVector) Prepend(e GqElement) *GqVector {
	newElems := make([]GqElement, len(v.elements)+1)
	newElems[0] = e
	copy(newElems[1:], v.elements)
	group := v.group
	if group == nil {
		group = e.group
	}
	return &GqVector{elements: newElems, group: group}
}

// SubVector returns a sub-vector [from, to).
func (v *GqVector) SubVector(from, to int) *GqVector {
	elems := make([]GqElement, to-from)
	copy(elems, v.elements[from:to])
	return &GqVector{elements: elems, group: v.group}
}

// Multiply returns element-wise product of two vectors.
func (v *GqVector) Multiply(other *GqVector) *GqVector {
	if v.Size() != other.Size() {
		panic("vectors must have same size")
	}
	result := make([]GqElement, v.Size())
	for i := range v.elements {
		result[i] = v.elements[i].Multiply(other.elements[i])
	}
	return &GqVector{elements: result, group: v.group}
}

// Exponentiate returns each element raised to the corresponding exponent.
func (v *GqVector) Exponentiate(exponents *ZqVector) *GqVector {
	if v.Size() != exponents.Size() {
		panic("vectors must have same size")
	}
	result := make([]GqElement, v.Size())
	for i := range v.elements {
		result[i] = v.elements[i].Exponentiate(exponents.elements[i])
	}
	return &GqVector{elements: result, group: v.group}
}

// ExpScalar returns each element raised to the same scalar exponent.
func (v *GqVector) ExpScalar(exponent ZqElement) *GqVector {
	result := make([]GqElement, v.Size())
	for i := range v.elements {
		result[i] = v.elements[i].Exponentiate(exponent)
	}
	return &GqVector{elements: result, group: v.group}
}

// Product returns the product of all elements.
func (v *GqVector) Product() GqElement {
	if v.Size() == 0 {
		panic("cannot take product of empty vector")
	}
	result := v.elements[0]
	for i := 1; i < len(v.elements); i++ {
		result = result.Multiply(v.elements[i])
	}
	return result
}

// Map applies fn to each element and returns a new vector.
func (v *GqVector) Map(fn func(GqElement) GqElement) *GqVector {
	result := make([]GqElement, v.Size())
	for i, e := range v.elements {
		result[i] = fn(e)
	}
	return &GqVector{elements: result, group: v.group}
}

// ParallelMap applies fn to each element in parallel.
func (v *GqVector) ParallelMap(fn func(GqElement) GqElement) *GqVector {
	result := make([]GqElement, v.Size())
	workers := runtime.NumCPU()
	if workers > v.Size() {
		workers = v.Size()
	}

	var wg sync.WaitGroup
	ch := make(chan int, v.Size())
	for i := 0; i < v.Size(); i++ {
		ch <- i
	}
	close(ch)

	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for i := range ch {
				result[i] = fn(v.elements[i])
			}
		}()
	}
	wg.Wait()
	return &GqVector{elements: result, group: v.group}
}

// ZqVector is a vector of ZqElements from the same group.
type ZqVector struct {
	elements []ZqElement
	group    *ZqGroup
}

// NewZqVector creates a new ZqVector, validating all elements are from the same group.
func NewZqVector(elements []ZqElement) (*ZqVector, error) {
	if len(elements) == 0 {
		return &ZqVector{elements: []ZqElement{}}, nil
	}
	group := elements[0].group
	for i, e := range elements {
		if !e.group.Equals(group) {
			return nil, fmt.Errorf("element %d is from a different group", i)
		}
	}
	copied := make([]ZqElement, len(elements))
	copy(copied, elements)
	return &ZqVector{elements: copied, group: group}, nil
}

// ZqVectorOf creates a ZqVector from variadic elements.
func ZqVectorOf(elements ...ZqElement) *ZqVector {
	if len(elements) == 0 {
		return &ZqVector{elements: []ZqElement{}}
	}
	copied := make([]ZqElement, len(elements))
	copy(copied, elements)
	return &ZqVector{elements: copied, group: elements[0].group}
}

// ZqVectorFromBigInts creates a ZqVector from big.Int values in the given group.
func ZqVectorFromBigInts(values []*big.Int, group *ZqGroup) (*ZqVector, error) {
	elements := make([]ZqElement, len(values))
	for i, v := range values {
		e, err := NewZqElement(v, group)
		if err != nil {
			return nil, fmt.Errorf("element %d: %w", i, err)
		}
		elements[i] = e
	}
	return &ZqVector{elements: elements, group: group}, nil
}

// ZqVectorOfZeros creates a vector of zero elements.
func ZqVectorOfZeros(size int, group *ZqGroup) *ZqVector {
	elements := make([]ZqElement, size)
	for i := range elements {
		elements[i] = group.Identity()
	}
	return &ZqVector{elements: elements, group: group}
}

// Size returns the number of elements.
func (v *ZqVector) Size() int {
	return len(v.elements)
}

// Get returns the element at index i.
func (v *ZqVector) Get(i int) ZqElement {
	return v.elements[i]
}

// Group returns the common group.
func (v *ZqVector) Group() *ZqGroup {
	return v.group
}

// Elements returns a copy of the elements slice.
func (v *ZqVector) Elements() []ZqElement {
	copied := make([]ZqElement, len(v.elements))
	copy(copied, v.elements)
	return copied
}

// Append creates a new vector with the element appended.
func (v *ZqVector) Append(e ZqElement) *ZqVector {
	newElems := make([]ZqElement, len(v.elements)+1)
	copy(newElems, v.elements)
	newElems[len(v.elements)] = e
	group := v.group
	if group == nil {
		group = e.group
	}
	return &ZqVector{elements: newElems, group: group}
}

// Prepend creates a new vector with the element prepended.
func (v *ZqVector) Prepend(e ZqElement) *ZqVector {
	newElems := make([]ZqElement, len(v.elements)+1)
	newElems[0] = e
	copy(newElems[1:], v.elements)
	group := v.group
	if group == nil {
		group = e.group
	}
	return &ZqVector{elements: newElems, group: group}
}

// SubVector returns a sub-vector [from, to).
func (v *ZqVector) SubVector(from, to int) *ZqVector {
	elems := make([]ZqElement, to-from)
	copy(elems, v.elements[from:to])
	return &ZqVector{elements: elems, group: v.group}
}

// Add returns element-wise sum of two vectors.
func (v *ZqVector) Add(other *ZqVector) *ZqVector {
	if v.Size() != other.Size() {
		panic("vectors must have same size")
	}
	result := make([]ZqElement, v.Size())
	for i := range v.elements {
		result[i] = v.elements[i].Add(other.elements[i])
	}
	return &ZqVector{elements: result, group: v.group}
}

// MultiplyElementWise returns element-wise product of two vectors.
func (v *ZqVector) MultiplyElementWise(other *ZqVector) *ZqVector {
	if v.Size() != other.Size() {
		panic("vectors must have same size")
	}
	result := make([]ZqElement, v.Size())
	for i := range v.elements {
		result[i] = v.elements[i].Multiply(other.elements[i])
	}
	return &ZqVector{elements: result, group: v.group}
}

// ScalarMultiply returns each element multiplied by the scalar.
func (v *ZqVector) ScalarMultiply(scalar ZqElement) *ZqVector {
	result := make([]ZqElement, v.Size())
	for i := range v.elements {
		result[i] = v.elements[i].Multiply(scalar)
	}
	return &ZqVector{elements: result, group: v.group}
}

// Sum returns the sum of all elements.
func (v *ZqVector) Sum() ZqElement {
	if v.Size() == 0 {
		panic("cannot sum empty vector")
	}
	result := v.elements[0]
	for i := 1; i < len(v.elements); i++ {
		result = result.Add(v.elements[i])
	}
	return result
}

// Product returns the product of all elements.
func (v *ZqVector) Product() ZqElement {
	if v.Size() == 0 {
		panic("cannot take product of empty vector")
	}
	result := v.elements[0]
	for i := 1; i < len(v.elements); i++ {
		result = result.Multiply(v.elements[i])
	}
	return result
}

// InnerProduct computes the inner product (dot product) of this vector with a GqVector.
// Returns Π(gq[i]^zq[i]).
func (v *ZqVector) InnerProduct(bases *GqVector) GqElement {
	if v.Size() != bases.Size() {
		panic("vectors must have same size")
	}
	return MultiModExp(bases.elements, v.elements)
}

// Map applies fn to each element.
func (v *ZqVector) Map(fn func(ZqElement) ZqElement) *ZqVector {
	result := make([]ZqElement, v.Size())
	for i, e := range v.elements {
		result[i] = fn(e)
	}
	return &ZqVector{elements: result, group: v.group}
}

// Negate returns a vector of negated elements.
func (v *ZqVector) Negate() *ZqVector {
	return v.Map(func(e ZqElement) ZqElement { return e.Negate() })
}
