package ru.kata.spring.boot_security.demo.model;

public enum Permission {
    DEVELOPERS_READ("developers:read"),
    DEVELOPERS_WRITE("developers:write")
    ;
    private final String permission;

    public String getPermission() {
        return permission;
    }

    Permission(String permission) {
        this.permission = permission;

    }
}
