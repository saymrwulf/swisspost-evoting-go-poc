package math

// GqMatrix is a matrix of GqElements.
type GqMatrix struct {
	rows    []*GqVector
	group   *GqGroup
	numRows int
	numCols int
}

// NewGqMatrix creates a matrix from rows.
func NewGqMatrix(rows []*GqVector) *GqMatrix {
	if len(rows) == 0 {
		panic("matrix must have at least one row")
	}
	numCols := rows[0].Size()
	for i, row := range rows {
		if row.Size() != numCols {
			panic("all rows must have the same size")
		}
		if i > 0 && !row.group.Equals(rows[0].group) {
			panic("all rows must be from the same group")
		}
	}
	copied := make([]*GqVector, len(rows))
	copy(copied, rows)
	return &GqMatrix{rows: copied, group: rows[0].group, numRows: len(rows), numCols: numCols}
}

// GqMatrixFromColumns creates a matrix from columns.
func GqMatrixFromColumns(columns []*GqVector) *GqMatrix {
	if len(columns) == 0 {
		panic("matrix must have at least one column")
	}
	numRows := columns[0].Size()
	rows := make([]*GqVector, numRows)
	for i := 0; i < numRows; i++ {
		elems := make([]GqElement, len(columns))
		for j, col := range columns {
			elems[j] = col.Get(i)
		}
		rows[i] = &GqVector{elements: elems, group: columns[0].group}
	}
	return NewGqMatrix(rows)
}

// NumRows returns the number of rows.
func (m *GqMatrix) NumRows() int {
	return m.numRows
}

// NumCols returns the number of columns.
func (m *GqMatrix) NumCols() int {
	return m.numCols
}

// Group returns the common group.
func (m *GqMatrix) Group() *GqGroup {
	return m.group
}

// Get returns the element at (row, col).
func (m *GqMatrix) Get(row, col int) GqElement {
	return m.rows[row].Get(col)
}

// GetRow returns a row as a GqVector.
func (m *GqMatrix) GetRow(i int) *GqVector {
	return m.rows[i]
}

// GetColumn returns a column as a GqVector.
func (m *GqMatrix) GetColumn(j int) *GqVector {
	elems := make([]GqElement, m.numRows)
	for i := 0; i < m.numRows; i++ {
		elems[i] = m.rows[i].Get(j)
	}
	return &GqVector{elements: elems, group: m.group}
}

// Transpose returns the transpose of this matrix.
func (m *GqMatrix) Transpose() *GqMatrix {
	rows := make([]*GqVector, m.numCols)
	for j := 0; j < m.numCols; j++ {
		rows[j] = m.GetColumn(j)
	}
	return &GqMatrix{rows: rows, group: m.group, numRows: m.numCols, numCols: m.numRows}
}

// AppendColumn creates a new matrix with a column appended.
func (m *GqMatrix) AppendColumn(column *GqVector) *GqMatrix {
	if column.Size() != m.numRows {
		panic("column size must match number of rows")
	}
	rows := make([]*GqVector, m.numRows)
	for i := 0; i < m.numRows; i++ {
		rows[i] = m.rows[i].Append(column.Get(i))
	}
	return NewGqMatrix(rows)
}

// PrependColumn creates a new matrix with a column prepended.
func (m *GqMatrix) PrependColumn(column *GqVector) *GqMatrix {
	if column.Size() != m.numRows {
		panic("column size must match number of rows")
	}
	rows := make([]*GqVector, m.numRows)
	for i := 0; i < m.numRows; i++ {
		rows[i] = m.rows[i].Prepend(column.Get(i))
	}
	return NewGqMatrix(rows)
}

// SubColumns returns a matrix with columns [from, to).
func (m *GqMatrix) SubColumns(from, to int) *GqMatrix {
	rows := make([]*GqVector, m.numRows)
	for i := 0; i < m.numRows; i++ {
		rows[i] = m.rows[i].SubVector(from, to)
	}
	return NewGqMatrix(rows)
}

// FlatElements returns all elements row by row.
func (m *GqMatrix) FlatElements() []GqElement {
	result := make([]GqElement, 0, m.numRows*m.numCols)
	for _, row := range m.rows {
		result = append(result, row.elements...)
	}
	return result
}

// ZqMatrix is a matrix of ZqElements.
type ZqMatrix struct {
	rows    []*ZqVector
	group   *ZqGroup
	numRows int
	numCols int
}

// NewZqMatrix creates a matrix from rows.
func NewZqMatrix(rows []*ZqVector) *ZqMatrix {
	if len(rows) == 0 {
		panic("matrix must have at least one row")
	}
	numCols := rows[0].Size()
	for _, row := range rows {
		if row.Size() != numCols {
			panic("all rows must have the same size")
		}
	}
	copied := make([]*ZqVector, len(rows))
	copy(copied, rows)
	return &ZqMatrix{rows: copied, group: rows[0].group, numRows: len(rows), numCols: numCols}
}

// ZqMatrixFromColumns creates a ZqMatrix from columns.
func ZqMatrixFromColumns(columns []*ZqVector) *ZqMatrix {
	if len(columns) == 0 {
		panic("matrix must have at least one column")
	}
	numRows := columns[0].Size()
	rows := make([]*ZqVector, numRows)
	for i := 0; i < numRows; i++ {
		elems := make([]ZqElement, len(columns))
		for j, col := range columns {
			elems[j] = col.Get(i)
		}
		rows[i] = &ZqVector{elements: elems, group: columns[0].group}
	}
	return NewZqMatrix(rows)
}

// NumRows returns the number of rows.
func (m *ZqMatrix) NumRows() int {
	return m.numRows
}

// NumCols returns the number of columns.
func (m *ZqMatrix) NumCols() int {
	return m.numCols
}

// Group returns the common group.
func (m *ZqMatrix) Group() *ZqGroup {
	return m.group
}

// Get returns the element at (row, col).
func (m *ZqMatrix) Get(row, col int) ZqElement {
	return m.rows[row].Get(col)
}

// GetRow returns a row as a ZqVector.
func (m *ZqMatrix) GetRow(i int) *ZqVector {
	return m.rows[i]
}

// GetColumn returns a column as a ZqVector.
func (m *ZqMatrix) GetColumn(j int) *ZqVector {
	elems := make([]ZqElement, m.numRows)
	for i := 0; i < m.numRows; i++ {
		elems[i] = m.rows[i].Get(j)
	}
	return &ZqVector{elements: elems, group: m.group}
}

// Transpose returns the transpose.
func (m *ZqMatrix) Transpose() *ZqMatrix {
	rows := make([]*ZqVector, m.numCols)
	for j := 0; j < m.numCols; j++ {
		rows[j] = m.GetColumn(j)
	}
	return &ZqMatrix{rows: rows, group: m.group, numRows: m.numCols, numCols: m.numRows}
}

// AppendColumn creates a new matrix with a column appended.
func (m *ZqMatrix) AppendColumn(column *ZqVector) *ZqMatrix {
	if column.Size() != m.numRows {
		panic("column size must match number of rows")
	}
	rows := make([]*ZqVector, m.numRows)
	for i := 0; i < m.numRows; i++ {
		rows[i] = m.rows[i].Append(column.Get(i))
	}
	return NewZqMatrix(rows)
}

// PrependColumn creates a new matrix with a column prepended.
func (m *ZqMatrix) PrependColumn(column *ZqVector) *ZqMatrix {
	if column.Size() != m.numRows {
		panic("column size must match number of rows")
	}
	rows := make([]*ZqVector, m.numRows)
	for i := 0; i < m.numRows; i++ {
		rows[i] = m.rows[i].Prepend(column.Get(i))
	}
	return NewZqMatrix(rows)
}

// SubColumns returns a matrix with columns [from, to).
func (m *ZqMatrix) SubColumns(from, to int) *ZqMatrix {
	rows := make([]*ZqVector, m.numRows)
	for i := 0; i < m.numRows; i++ {
		rows[i] = m.rows[i].SubVector(from, to)
	}
	return NewZqMatrix(rows)
}

// FlatElements returns all elements row by row.
func (m *ZqMatrix) FlatElements() []ZqElement {
	result := make([]ZqElement, 0, m.numRows*m.numCols)
	for _, row := range m.rows {
		result = append(result, row.elements...)
	}
	return result
}

// VectorToGqMatrix reshapes a flat GqVector into a matrix of numRows x numCols.
func VectorToGqMatrix(v *GqVector, numRows, numCols int) *GqMatrix {
	if v.Size() != numRows*numCols {
		panic("vector size must equal numRows * numCols")
	}
	rows := make([]*GqVector, numRows)
	for i := 0; i < numRows; i++ {
		rows[i] = v.SubVector(i*numCols, (i+1)*numCols)
	}
	return NewGqMatrix(rows)
}

// VectorToZqMatrix reshapes a flat ZqVector into a matrix.
func VectorToZqMatrix(v *ZqVector, numRows, numCols int) *ZqMatrix {
	if v.Size() != numRows*numCols {
		panic("vector size must equal numRows * numCols")
	}
	rows := make([]*ZqVector, numRows)
	for i := 0; i < numRows; i++ {
		rows[i] = v.SubVector(i*numCols, (i+1)*numCols)
	}
	return NewZqMatrix(rows)
}
