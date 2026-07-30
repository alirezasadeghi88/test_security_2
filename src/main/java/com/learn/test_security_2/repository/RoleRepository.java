package com.learn.test_security_2.repository;

import com.learn.test_security_2.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {


    Optional<Role> findByCode(String code);
    Optional<Role> findByName(String name);
    boolean existsByCode(String code);
    boolean existsByName(String name);
    List<Role> findAllByActiveTrue();

}
