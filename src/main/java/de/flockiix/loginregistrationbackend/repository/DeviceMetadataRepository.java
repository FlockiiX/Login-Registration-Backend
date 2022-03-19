package de.flockiix.loginregistrationbackend.repository;

import de.flockiix.loginregistrationbackend.model.DeviceMetadata;
import de.flockiix.loginregistrationbackend.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface DeviceMetadataRepository extends JpaRepository<DeviceMetadata, Long> {
    @Query("SELECT dmd FROM DeviceMetadata dmd WHERE dmd.user = ?1")
    List<DeviceMetadata> findDeviceMetadataByUser(User user);
}
