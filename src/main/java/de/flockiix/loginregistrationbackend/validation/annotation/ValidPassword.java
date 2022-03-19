package de.flockiix.loginregistrationbackend.validation.annotation;

import de.flockiix.loginregistrationbackend.validation.validator.PasswordValidator;

import javax.validation.Constraint;
import javax.validation.Payload;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import static java.lang.annotation.ElementType.*;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

@Target({TYPE, FIELD, ANNOTATION_TYPE})
@Retention(RUNTIME)
@Constraint(validatedBy = PasswordValidator.class)
public @interface ValidPassword {
    String message() default "Weak Password";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}
