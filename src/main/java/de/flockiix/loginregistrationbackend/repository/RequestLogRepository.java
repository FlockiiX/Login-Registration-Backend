package de.flockiix.loginregistrationbackend.repository;

import de.flockiix.loginregistrationbackend.model.RequestLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RequestLogRepository extends JpaRepository<RequestLog, Long> {

}
