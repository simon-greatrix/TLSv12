package tlsv12.math.field;

public interface PolynomialExtensionField extends FiniteField
{
    Polynomial getMinimalPolynomial();
}
