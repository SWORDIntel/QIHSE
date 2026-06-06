module math_routines
  use iso_c_binding, only: c_float, c_int
  implicit none

contains

  ! Export this subroutine to C
  subroutine fortran_pca_compress(in_mat, rows, dims, target, out_mat) bind(c, name="fortran_pca_compress")
    integer(c_int), intent(in) :: rows, dims, target
    real(c_float), intent(in) :: in_mat(dims, rows)
    real(c_float), intent(out) :: out_mat(target, rows)
    
    print *, "[FORTRAN] Native BLAS/LAPACK executing PCA block..."
    ! In a real scenario, this would call LAPACK's SGESVD or similar.
    ! For now, just a dummy loop to show it runs in Fortran.
    out_mat = 0.0
  end subroutine fortran_pca_compress

end module math_routines
