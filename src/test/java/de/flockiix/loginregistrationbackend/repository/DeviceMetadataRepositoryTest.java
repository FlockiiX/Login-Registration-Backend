package de.flockiix.loginregistrationbackend.repository;

import de.flockiix.loginregistrationbackend.model.DeviceMetadata;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;

import java.util.ArrayList;
import java.util.List;

import static de.flockiix.loginregistrationbackend.util.TestUtils.getUser;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

@DataJpaTest
class DeviceMetadataRepositoryTest {
    private final DeviceMetadataRepository deviceMetadataRepository;
    private final UserRepository userRepository;

    @Autowired
    DeviceMetadataRepositoryTest(DeviceMetadataRepository deviceMetadataRepository, UserRepository userRepository) {
        this.deviceMetadataRepository = deviceMetadataRepository;
        this.userRepository = userRepository;
    }

    @Test
    void findDeviceMetadataByUser() {
        var user = userRepository.save(getUser());
        List<DeviceMetadata> expected = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            var deviceMetadata = new DeviceMetadata(
                    "0.0.0." + i,
                    "None",
                    "Earth",
                    user
            );

            expected.add(deviceMetadata);
            deviceMetadataRepository.save(deviceMetadata);
        }

        var actual = deviceMetadataRepository.findDeviceMetadataByUser(user);
        assertThat(actual).isEqualTo(expected);
    }
}